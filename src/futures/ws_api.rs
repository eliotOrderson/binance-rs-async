#![allow(warnings, unused)]
use std::collections::btree_map::BTreeMap;
use std::sync::Arc;

use base64::prelude::*;
use ed25519_dalek::{pkcs8::{spki::der::pem::LineEnding, DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
                    Signer as _, SigningKey};

use serde::de;
use serde::de::DeserializeOwned;
use serde_json::from_str;

use futures::{SinkExt, StreamExt};
use hex::encode;

use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream};
use url::Url;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::errors::{BinanceContentError, Error, Result};
use crate::futures::account::OrderRequest;
use crate::futures::rest_model::{OrderSide, Position, Transaction};
use crate::rest_model::RateLimit;

use super::ws_model::PriceMatch;

pub fn generate_ed25519_key() {}

#[derive(Debug, PartialEq, Eq)]
enum Authorization {
    Signature,
    ApiKey,
    // signature and apikey
    Both,
    None,
}

#[derive(Debug, Serialize)]
enum Method {
    #[serde(rename = "session.status")]
    SessionStatus,

    #[serde(rename = "session.logon")]
    SessionLogon,

    #[serde(rename = "session.logout")]
    SessionLogout,

    // order: submit, cancel, query, modify
    #[serde(rename = "order.place")]
    OrderPlace,

    #[serde(rename = "order.cancel")]
    OrderCancel,

    #[serde(rename = "order.status")]
    OrderQuery,

    // if require modification order then maybe should not be submition.
    // #[serde(rename = "order.modify")]
    // OrderModify,
    #[serde(rename = "account.position")]
    AccountPosition,

    // user stram
    #[serde(rename = "userDataStream.start")]
    UserDataStreamStart,

    #[serde(rename = "userDataStream.ping")]
    UserDataStreamKeepAlive,

    #[serde(rename = "userDataStream.stop")]
    UserDataStreamStop,
}

impl Method {
    // authorization authentication (signature or apiKey, none)
    pub fn require_authorization(&self) -> Authorization {
        match self {
            Method::SessionStatus | Method::SessionLogout => Authorization::None,
            Method::UserDataStreamStart | Method::UserDataStreamKeepAlive | Method::UserDataStreamStop => {
                Authorization::ApiKey
            }

            Method::OrderPlace
            | Method::OrderCancel
            | Method::OrderQuery
            | Method::AccountPosition
            | Method::SessionLogon => Authorization::Both,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WsRequest<P> {
    pub id: String,
    pub method: Method,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<P>,
}

#[derive(Default, Debug, Deserialize)]
pub struct WsResponse<Rlt> {
    pub id: String,
    // if connection is normal then status always 200.
    pub status: i32,
    pub method: Option<String>,
    pub result: Option<Rlt>,
    pub error: Option<BinanceContentError>,
    pub rate_limits: Option<Vec<RateLimit>>,
}

pub struct FuturesWebSocketApi {
    // response info in first connection.
    pub response: Option<Response>,

    // pub socket: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    socket: Option<Arc<Mutex<WebSocketStream<MaybeTlsStream<TcpStream>>>>>,

    conf: Config,

    sign: Box<dyn Fn(&[u8]) -> String>,

    // logon supportion only with ed25519 key
    api_key: String,
    auto_logon: bool,
}

impl FuturesWebSocketApi {
    pub fn new_with_options<S1, S2>(api_key: S1, secret_key: S2, conf: Config) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        let secret_key = secret_key.into() as String;
        let signed_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret_key.as_bytes());
        let sign = move |request: &[u8]| hex::encode(ring::hmac::sign(&signed_key, request).as_ref());
        Self {
            conf,
            sign: Box::new(sign),
            socket: None,
            api_key: api_key.into(),
            response: None,
            auto_logon: false,
        }
    }

    /// logon only used of ed25519, if not have the key, can use '[generate_ed25519_key]' gain it.
    /// if logon for true then not require signature on per request.
    pub fn new_with_ed25519_options<S1, S2>(auto_logon: bool, api_key: S1, private_key_pem: S2, conf: Config) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        let secret_key = (private_key_pem.into() as String)
            .split("\n")
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
            .join("\n");

        let signer = SigningKey::from_pkcs8_pem(secret_key.as_str()).unwrap();
        let sign = move |query_str: &[u8]| BASE64_STANDARD.encode(signer.sign(query_str).to_bytes());
        Self {
            conf,
            sign: Box::new(sign),
            socket: None,
            api_key: api_key.into(),
            response: None,
            auto_logon,
        }
    }

    pub async fn auto_check_connection(socket: Arc<Mutex<WebSocketStream<MaybeTlsStream<TcpStream>>>>) {
        loop {
            {
                let utc = chrono::Utc::now();
                let timestamp = utc.timestamp().to_string().as_bytes().to_vec();

                let mut sk = socket.lock().await;
                let ping_result = sk.send(Message::Ping(timestamp)).await;
                println!("ping: {:?}", utc);

                match sk.select_next_some().await {
                    Ok(message) => {
                        if let Message::Ping(ping) = message {
                            let datetime = chrono::NaiveDateTime::from_timestamp_millis(
                                String::from_utf8(ping.clone()).unwrap().parse::<i64>().unwrap(),
                            );
                            let datetime = datetime.unwrap();
                            println!("{}", datetime);

                            let pong_result = sk.send(Message::Pong(ping)).await;
                            println!("send pong: {:?}", pong_result);
                        }
                    }
                    Err(e) => println!("check error: {e:?}\n"),
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(6000)).await;
        }
    }

    // response result:
    // "apiKey": String,
    // "connectedSince": u64,
    // "authorizedSince": u64,
    // "returnRateLimits": bool,
    // "serverTime": u64
    pub async fn status(&mut self) -> Result<serde_json::Value> {
        let req = WsRequest::<i8> {
            id: "check_session_status".into(),
            method: Method::SessionStatus,
            params: None,
        };

        let mut rsp = self.send(!self.auto_logon, &[req]).await?;
        self.unwrap_result(&mut rsp[0]).await
    }

    // logon supportion only with ed25519 key
    // response result similar status func result
    pub async fn logon(&mut self) -> Result<serde_json::Value> {
        let logon_req = WsRequest {
            id: "ed25519key_logon".into(),
            method: Method::SessionLogon,
            params: Some(serde_json::json!({
                "apiKey": self.api_key.clone()
            })),
        };

        let mut logon_rsp = self.send(self.auto_logon, &[logon_req]).await?;
        self.unwrap_result(&mut logon_rsp[0]).await
    }

    pub async fn logout(&mut self) -> Result<()> {
        let req = WsRequest::<i8> {
            id: "logout".into(),
            method: Method::SessionStatus,
            params: None,
        };

        let mut rsp = self.send::<serde_json::Value, _>(!self.auto_logon, &[req]).await?;
        self.unwrap_result(&mut rsp[0]).await?;
        Ok(())
    }

    pub async fn place_order(&mut self, order: OrderRequest) -> Result<Transaction> {
        let mut rsp = self.place_batch_orders(vec![order]).await?;
        Ok(rsp.pop().unwrap())
    }

    pub async fn place_batch_orders(&mut self, orders: Vec<OrderRequest>) -> Result<Vec<Transaction>> {
        let mut batch_orders = vec![];
        for order in orders {
            let mut order = serde_json::to_value(order)?;
            let order_map = order.as_object_mut().unwrap();

            // websocket api require decimal(f64) for json string.
            for value in order_map.values_mut() {
                if value.is_f64() {
                    *value = serde_json::Value::String(value.to_string());
                }
            }

            batch_orders.push(WsRequest {
                id: "submit_order".into(),
                method: Method::OrderPlace,
                params: Some(order),
            });
        }

        let mut rsps = self.send::<Transaction, _>(!self.auto_logon, &batch_orders).await?;
        let mut batch_trans = vec![];
        for rsp in rsps.iter_mut() {
            batch_trans.push(self.unwrap_result(rsp).await?);
        }
        Ok(batch_trans)
    }

    /// the id can be order_id or client_order_id
    pub async fn cancel_order<S, T>(&mut self, symbol: S, id: T) -> Result<Transaction>
    where
        S: Into<String>,
        T: ToString,
    {
        use serde_json::{Number, Value};

        let primary_key = id.to_string();
        let mut params = BTreeMap::from([("symbol", Value::String(symbol.into()))]);
        match primary_key.parse::<u64>() {
            Ok(order_id) => params.insert("orderId", Value::Number(Number::from(order_id))),
            Err(_) => params.insert("origClientOrderId", Value::String(primary_key)),
        };

        let req = WsRequest {
            id: "cancel_order".into(),
            method: Method::OrderCancel,
            params: Some(params),
        };

        let mut rsp = self.send::<Transaction, _>(!self.auto_logon, &[req]).await?;
        self.unwrap_result(&mut rsp[0]).await
    }

    pub async fn position_info<S: Into<String>>(&mut self, symbol: S) -> Result<Vec<Position>> {
        let req = WsRequest {
            id: "query_position_info".into(),
            method: Method::AccountPosition,
            params: Some(serde_json::json!({
                "symbol":  symbol.into()
            })),
        };

        let mut rsp = self.send(!self.auto_logon, &[req]).await?;
        self.unwrap_result(&mut rsp[0]).await
    }

    pub async fn listen_key(&mut self) -> Result<String> {
        let req = WsRequest {
            id: "generate_listen_key".into(),
            method: Method::UserDataStreamStart,
            params: Some(serde_json::json!({})),
        };

        let mut rsp = self
            .send::<BTreeMap<String, String>, _>(!self.auto_logon, &[req])
            .await?;
        let result = self.unwrap_result(&mut rsp[0]).await?;
        // if request not had error then it surely not be none.
        Ok(result["listenKey"].clone())
    }

    pub async fn keep_alive_listen_key(&mut self, listen_key: &str) -> Result<()> {
        let req = WsRequest {
            id: "keep_alive_listen_key".into(),
            method: Method::UserDataStreamKeepAlive,
            params: Some(serde_json::json!({
                "listenKey": listen_key
            })),
        };

        let mut rsp = self.send::<serde_json::Value, _>(!self.auto_logon, &[req]).await?;
        self.unwrap_result(&mut rsp[0]).await?;
        Ok(())
    }

    pub async fn close_listen_key(&mut self, listen_key: &str) -> Result<()> {
        let req = WsRequest {
            id: "close_listen_key".into(),
            method: Method::UserDataStreamStop,
            params: Some(serde_json::json!({
                "listenKey": listen_key
            })),
        };

        let mut rsp = self.send::<serde_json::Value, _>(!self.auto_logon, &[req]).await?;
        self.unwrap_result(&mut rsp[0]).await?;
        Ok(())
    }

    pub async fn connect(&mut self, return_rate_limits: bool) -> Result<()> {
        let params = format!("?returnRateLimits={}", return_rate_limits);
        let url = Url::parse(&format!("{}{}", self.conf.futures_ws_api_endpoint, params))?;
        println!("connect url: {}", url);

        self.handle_connect(url).await?;

        if self.auto_logon {
            self.logon().await?;
        }
        Ok(())
    }

    // handle error and unwrap result
    pub async fn unwrap_result<T: std::fmt::Debug>(&self, rsp: &mut WsResponse<T>) -> Result<T> {
        // println!("{:?}\n", rsp);
        if let Some(err) = std::mem::take(&mut rsp.error) {
            return Err(Error::BinanceError { response: err });
        }
        Ok(std::mem::take(&mut rsp.result).unwrap())
    }

    /// Disconnect from the endpoint
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(ref mut socket) = self.socket {
            socket.lock().await.close(None).await?;
            Ok(())
        } else {
            Err(Error::Msg("Not able to close the connection".to_string()))
        }
    }

    /// Connect to a websocket endpoint
    async fn handle_connect(&mut self, url: Url) -> Result<()> {
        let mut answer = connect_async(url)
            .await
            .map_err(|e| Error::Msg(format!("Error during handshake {e}")))?;

        let socket = Arc::new(Mutex::new(answer.0));
        tokio::spawn(Self::auto_check_connection(socket.clone()));
        self.socket = Some(socket);
        self.response = Some(answer.1);
        Ok(())
    }

    pub async fn send<Rlt, Params>(
        &mut self,
        auto_signature: bool,
        reqs: &[WsRequest<Params>],
    ) -> Result<Vec<WsResponse<Rlt>>>
    where
        Params: Serialize,
        Rlt: de::DeserializeOwned,
    {
        if self.socket.is_none() {
            return Err(Error::Msg("websocket not connection.".into()));
        }

        let mut result = vec![];
        let mut wait_time = reqs.len();
        let mut socket = self.socket.as_mut().unwrap().lock().await;

        let timestamp = chrono::Utc::now().timestamp_millis();

        // check connection
        socket
            .send(Message::Ping(timestamp.to_string().as_bytes().into()))
            .await?;

        for req in reqs {
            let request_json = {
                let mut request = serde_json::to_value(&req)?;
                let authorization = req.method.require_authorization();

                if authorization != Authorization::None {
                    use serde_json::{Number, Value};

                    // if json has correct then request always Some.
                    let req_map = request.as_object_mut().unwrap();

                    let timestamp_micros = chrono::Utc::now().timestamp_micros();
                    let new_id = format!("{}_{}", req.id, timestamp_micros);
                    req_map.insert("id".into(), Value::String(new_id));

                    // if require authorization then it always some.
                    let params = req_map.get_mut("params").unwrap().as_object_mut().unwrap();

                    params.insert("timestamp".into(), Value::Number(Number::from(timestamp)));
                    params.insert("recvWindow".into(), Value::Number(Number::from(self.conf.recv_window)));

                    if auto_signature {
                        let mut fill_auth = |event: Authorization| -> Result<()> {
                            match event {
                                Authorization::Signature => {
                                    let signature = (self.sign)(qs::to_string(params)?.as_bytes());
                                    params.insert("signature".into(), Value::String(signature));
                                }
                                Authorization::ApiKey => {
                                    params.insert("apiKey".into(), Value::String(self.api_key.clone()));
                                }
                                // always nothing
                                Authorization::None | Authorization::Both => todo!(),
                            }
                            Ok(())
                        };

                        match authorization {
                            Authorization::Both => {
                                fill_auth(Authorization::ApiKey)?;
                                fill_auth(Authorization::Signature)?;
                            }
                            _ => fill_auth(authorization)?,
                        };
                    }
                }

                request.to_string()
            };

            println!("{}\n", request_json);
            socket.send(Message::Text(request_json)).await?
        }

        while wait_time != 0 {
            let message = socket.select_next_some().await?;
            match message {
                Message::Text(rsp) => {
                    // println!(
                    //     "{}\n",
                    //     serde_json::to_string_pretty(&serde_json::from_str::<'_, serde_json::Value>(&rsp).unwrap())
                    //         .unwrap()
                    // );
                    result.push(serde_json::from_str::<'_, WsResponse<Rlt>>(&rsp)?);
                    wait_time -= 1;
                }
                Message::Ping(ping) => socket.send(Message::Pong(ping)).await?,
                Message::Close(e) => return Err(Error::Msg(format!("Disconnected {e:?}"))),
                _ => (),
            }
        }

        Ok(result)
    }
}

mod tests {
    use super::*;
    #[tokio::test]
    async fn abcd() {
        let ed25519_api = "34teJAMVsR7HiXBc5ywoem7w6XB71yAXfepB9ZWaLag2KnAIL7yQD5gdFeCu4xVT";
        let ed25519_secret = r#"
    -----BEGIN PRIVATE KEY-----
        MFECAQEwBQYDK2VwBCIEIPPm7oLpAIuB6dHRmkAgc0Kc19kHjgZXVY/WkxrmhomY
        gSEAuTvsNaYVR4Gca4dv1KKJEcKtx+clikSqNqOs804Mwmo=
    -----END PRIVATE KEY-----"#;

        let return_rate_limits = false;
        let cfg = super::Config::default();
        let mut ws_api = FuturesWebSocketApi::new_with_ed25519_options(true, ed25519_api, ed25519_secret, cfg);
        ws_api.connect(return_rate_limits).await.unwrap();
        // println!("{:?}\n", ws_api.position_info("BTCUSDT").await.unwrap());
        println!("{:?}\n", ws_api.status().await);

        let lk = ws_api.listen_key().await.unwrap();
        // println!("{}", lk);
        // println!("{:?}\n", ws_api.keep_alive_listen_key(&lk).await.unwrap());
        println!("{:?}\n", ws_api.close_listen_key(&lk).await.unwrap());

        tokio::signal::ctrl_c().await;
        ws_api.disconnect().await;
        //
        // let timestamp = chrono::Utc::now().timestamp_millis();
        // let mut params = BTreeMap::from([
        //     ("apiKey", Value::String(ed_25519_api_key.to_string())),
        //     // ("symbol", Value::String("BTCUSDT".into())),
        //     ("timestamp", Value::Number(Number::from(timestamp))),
        // ]);
        //
        // let query_str = qs::to_string(&params).unwrap();
        // let signature_bytes = signer.sign(query_str.as_bytes()).to_bytes();
        // let signature_base64 = BASE64_STANDARD.encode(signature_bytes);
        // params.insert("signature", Value::String(signature_base64));
        //
        // let req = WsRequest::<BTreeMap<&str, serde_json::Value>> {
        //     id: "123".into(),
        //     method: Method::SessionLogon,
        //     params: Some(params),
        // };
        //
        // let req_str = serde_json::to_string(&req).unwrap();
        // println!("request json: {}\n", req_str);
        //
        // sk.send(Message::Text(req_str)).await.unwrap();
        //
        // let req = WsRequest::<BTreeMap<&str, serde_json::Value>> {
        //     id: "123".into(),
        //     method: Method::SessionStatus,
        //     params: None,
        // };
        //
        // let req_str = serde_json::to_string(&req).unwrap();
        // sk.send(Message::Text(req_str)).await.unwrap();
        // println!("{:?}", sk.next().await.unwrap());
        // println!("{:?}", sk.next().await.unwrap());
    }

    // #[tokio::test]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ras_key() {
        use crate::futures::rest_model::{OrderSide, OrderType, TimeInForce};
        let api_key = "08ab49f1a3aad866e212428f348a6810b65268241cc0449912bb46c8e0198314";
        let secret_key = "f9eacfff89deb907d55a1a70abd5d0fd6907b96863c4842a4612828122bf5ce0";

        let return_rate_limits = false;
        let cfg = super::Config::testnet();
        let mut ws_api = super::FuturesWebSocketApi::new_with_options(api_key, secret_key, cfg);
        ws_api.connect(return_rate_limits).await.unwrap();

        // println!("{:?}\n", ws_api.position_info("BTCUSDT").await.unwrap());
        // println!(
        //     "{:?}",
        //     ws_api
        //         .place_batch_orders(vec![
        //             OrderRequest {
        //                 symbol: "BTCUSDT".into(),
        //                 price: Some(60001.),
        //                 quantity: Some(0.01),
        //                 side: OrderSide::Buy,
        //                 order_type: OrderType::Limit,
        //                 time_in_force: Some(TimeInForce::GTC),
        //                 position_side: None,
        //                 reduce_only: None,
        //                 stop_price: None,
        //                 close_position: None,
        //                 activation_price: None,
        //                 callback_rate: None,
        //                 working_type: None,
        //                 price_protect: None,
        //                 new_client_order_id: None,
        //             },
        //             OrderRequest {
        //                 symbol: "BTCUSDT".into(),
        //                 price: Some(59000.),
        //                 quantity: Some(0.01),
        //                 side: OrderSide::Sell,
        //                 order_type: OrderType::Stop,
        //                 time_in_force: Some(TimeInForce::GTC),
        //                 position_side: None,
        //                 reduce_only: Some(true),
        //                 stop_price: Some(59000.),
        //                 close_position: None,
        //                 activation_price: None,
        //                 callback_rate: None,
        //                 working_type: None,
        //                 price_protect: None,
        //                 new_client_order_id: None,
        //             },
        //             OrderRequest {
        //                 symbol: "BTCUSDT".into(),
        //                 price: None,
        //                 quantity: Some(0.01),
        //                 side: OrderSide::Sell,
        //                 order_type: OrderType::TakeProfitMarket,
        //                 time_in_force: Some(TimeInForce::GTC),
        //                 position_side: None,
        //                 reduce_only: Some(true),
        //                 stop_price: Some(64000.),
        //                 close_position: None,
        //                 activation_price: None,
        //                 callback_rate: None,
        //                 working_type: None,
        //                 price_protect: None,
        //                 new_client_order_id: None,
        //             }
        //         ],)
        //         .await
        //         .unwrap()
        // );

        tokio::signal::ctrl_c().await;
        ws_api.disconnect().await;
    }
}
