use std::collections::BTreeMap;

use super::rest_model::{AccountBalance, AccountInformation, CanceledOrder, ChangeLeverageResponse, Order, OrderType,
                        Position, PositionSide, Transaction, WorkingType};
use crate::account::OrderCancellation;
use crate::client::Client;
use crate::errors::*;
use crate::rest_model::{OrderSide, TimeInForce};
use crate::rest_model::{PairAndWindowQuery, PairQuery};
use crate::util::*;
use serde::Serializer;
use std::fmt;

#[derive(Clone)]
pub struct FuturesAccount {
    pub client: Client,
    pub recv_window: u64,
}

/// Serialize bool as str
fn serialize_as_str<S, T>(t: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
    T: fmt::Display,
{
    serializer.collect_str(t)
}

/// Serialize opt bool as str
fn serialize_opt_as_uppercase<S, T>(t: &Option<T>, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
    T: ToString,
{
    match *t {
        Some(ref v) => serializer.serialize_some(&v.to_string().to_uppercase()),
        None => serializer.serialize_none(),
    }
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GetOrderRequest {
    pub symbol: String,
    #[serde(rename = "orderId")]
    pub order_id: Option<String>,
    #[serde(rename = "origClientOrderId")]
    pub orig_client_order_id: Option<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OrderRequest {
    pub symbol: String,
    pub side: OrderSide,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_side: Option<PositionSide>,
    #[serde(rename = "type")]
    pub order_type: OrderType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_in_force: Option<TimeInForce>,

    #[serde(rename = "quantity")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduce_only: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_price: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_position: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_price: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_rate: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_type: Option<WorkingType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_opt_as_uppercase")]
    pub price_protect: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_client_order_id: Option<String>,
}

impl Into<OrderRequest> for Order {
    fn into(self) -> OrderRequest {
        let not_auto_close = self.close_position == false;
        OrderRequest {
            symbol: self.symbol,
            side: self.side,
            position_side: Some(self.position_side),
            order_type: self.order_type,
            time_in_force: Some(TimeInForce::GTC),
            quantity: Some(self.orig_qty),
            reduce_only: not_auto_close.then_some(self.reduce_only),
            price: not_auto_close.then_some(self.price),
            stop_price: Some(self.stop_price),
            close_position: Some(self.close_position),
            activation_price: Some(self.activate_price),
            callback_rate: Some(self.price_rate),
            working_type: Some(self.working_type),
            price_protect: Some(self.price_protect),
            new_client_order_id: Some(self.client_order_id),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangePositionModeRequest {
    #[serde(serialize_with = "serialize_as_str")]
    pub dual_side_position: bool,
}

impl FuturesAccount {
    /// Get an order
    pub async fn get_order(&self, order: Option<GetOrderRequest>) -> Result<Transaction> {
        self.client
            .get_signed_p("/fapi/v1/order", order, self.recv_window)
            .await
    }

    /// Place an order
    pub async fn place_order(&self, order: OrderRequest) -> Result<Transaction> {
        self.client
            .post_signed_p("/fapi/v1/order", order, self.recv_window)
            .await
    }

    /// Get currently open orders
    pub async fn get_open_orders(&self, symbol: impl Into<String>) -> Result<Vec<Order>> {
        let payload = build_signed_request_p([("symbol", symbol.into())], self.recv_window)?;
        self.client.get_signed("/fapi/v1/openOrders", &payload).await
    }

    /// Place a test order    
    pub async fn place_order_test(&self, order: OrderRequest) -> Result<Transaction> {
        self.client
            .post_signed_p("/fapi/v1/order/test", order, self.recv_window)
            .await
    }

    /// Place a limit buy order
    pub async fn limit_buy(
        &self,
        symbol: impl Into<String>,
        qty: impl Into<f64>,
        price: f64,
        time_in_force: TimeInForce,
    ) -> Result<Transaction> {
        let order = OrderRequest {
            symbol: symbol.into(),
            side: OrderSide::Buy,
            position_side: None,
            order_type: OrderType::Limit,
            time_in_force: Some(time_in_force),
            quantity: Some(qty.into()),
            reduce_only: None,
            price: Some(price),
            stop_price: None,
            close_position: None,
            activation_price: None,
            callback_rate: None,
            working_type: None,
            price_protect: None,
            new_client_order_id: None,
        };
        self.place_order(order).await
    }

    /// Place a limit sell order
    pub async fn limit_sell(
        &self,
        symbol: impl Into<String>,
        qty: impl Into<f64>,
        price: f64,
        time_in_force: TimeInForce,
    ) -> Result<Transaction> {
        let order = OrderRequest {
            symbol: symbol.into(),
            side: OrderSide::Sell,
            position_side: None,
            order_type: OrderType::Limit,
            time_in_force: Some(time_in_force),
            quantity: Some(qty.into()),
            reduce_only: None,
            price: Some(price),
            stop_price: None,
            close_position: None,
            activation_price: None,
            callback_rate: None,
            working_type: None,
            price_protect: None,
            new_client_order_id: None,
        };
        self.place_order(order).await
    }

    /// Place a Market buy order
    pub async fn market_buy<S, F>(&self, symbol: S, qty: F) -> Result<Transaction>
    where
        S: Into<String>,
        F: Into<f64>,
    {
        let order = OrderRequest {
            symbol: symbol.into(),
            side: OrderSide::Buy,
            position_side: None,
            order_type: OrderType::Market,
            time_in_force: None,
            quantity: Some(qty.into()),
            reduce_only: None,
            price: None,
            stop_price: None,
            close_position: None,
            activation_price: None,
            callback_rate: None,
            working_type: None,
            price_protect: None,
            new_client_order_id: None,
        };
        self.place_order(order).await
    }

    /// Place a Market sell order
    pub async fn market_sell<S, F>(&self, symbol: S, qty: F) -> Result<Transaction>
    where
        S: Into<String>,
        F: Into<f64>,
    {
        let order: OrderRequest = OrderRequest {
            symbol: symbol.into(),
            side: OrderSide::Sell,
            position_side: None,
            order_type: OrderType::Market,
            time_in_force: None,
            quantity: Some(qty.into()),
            reduce_only: None,
            price: None,
            stop_price: None,
            close_position: None,
            activation_price: None,
            callback_rate: None,
            working_type: None,
            price_protect: None,
            new_client_order_id: None,
        };
        self.place_order(order).await
    }

    /// Place a cancellation order
    pub async fn cancel_order(&self, o: OrderCancellation) -> Result<CanceledOrder> {
        self.client
            .delete_signed_p("/fapi/v1/order", &o, self.recv_window)
            .await
    }

    /// Get current position risk for the symbol
    pub async fn position_information<S>(&self, symbol: S) -> Result<Vec<Position>>
    where
        S: Into<String>,
    {
        self.client
            .get_signed_p(
                "/fapi/v2/positionRisk",
                Some(PairAndWindowQuery {
                    symbol: symbol.into(),
                    recv_window: self.recv_window,
                }),
                self.recv_window,
            )
            .await
    }

    /// Return general [`AccountInformation`]
    pub async fn account_information(&self) -> Result<AccountInformation> {
        // needs to be changed to smth better later
        let payload = build_signed_request(BTreeMap::<String, String>::new(), self.recv_window)?;
        self.client.get_signed_d("/fapi/v2/account", &payload).await
    }

    /// Return account's [`AccountBalance`]
    pub async fn account_balance(&self) -> Result<Vec<AccountBalance>> {
        let parameters = BTreeMap::<String, String>::new();
        let request = build_signed_request(parameters, self.recv_window)?;
        self.client.get_signed_d("/fapi/v2/balance", request.as_str()).await
    }

    /// Change the initial leverage for the symbol
    pub async fn change_initial_leverage<S>(&self, symbol: S, leverage: u8) -> Result<ChangeLeverageResponse>
    where
        S: Into<String>,
    {
        let mut parameters: BTreeMap<String, String> = BTreeMap::new();
        parameters.insert("symbol".into(), symbol.into());
        parameters.insert("leverage".into(), leverage.to_string());

        let request = build_signed_request(parameters, self.recv_window)?;
        self.client.post_signed_d("/fapi/v1/leverage", request.as_str()).await
    }

    /// Change the dual position side
    pub async fn change_position_mode(&self, dual_side_position: bool) -> Result<()> {
        self.client
            .post_signed_p(
                "/fapi/v1/positionSide/dual",
                ChangePositionModeRequest { dual_side_position },
                self.recv_window,
            )
            .await?;
        Ok(())
    }

    /// Cancel all open orders on this symbol
    pub async fn cancel_all_open_orders<S>(&self, symbol: S) -> Result<()>
    where
        S: Into<String>,
    {
        self.client
            .delete_signed_p::<crate::rest_model::Success, _>(
                "/fapi/v1/allOpenOrders",
                PairQuery { symbol: symbol.into() },
                self.recv_window,
            )
            .await?;
        Ok(())
    }

    pub async fn place_batch_orders(&self, orders: Vec<OrderRequest>) -> Result<Vec<Transaction>> {
        let mut batch_orders = vec![];
        for order in orders {
            batch_orders.push(serialize_and_jsonf64_to_jsonstr(order)?);
        }

        let request = BTreeMap::from([("batchOrders", serde_json::to_string(&batch_orders)?)]);
        self.client
            .post_signed_p("/fapi/v1/batchOrders", request, self.recv_window)
            .await
    }
}

mod tests {
    #![allow(warnings, unused)]
    use super::*;

    #[tokio::test]
    async fn name() {
        let cfg = crate::config::Config::testnet();
        let api_key: Option<String> = Some("08ab49f1a3aad866e212428f348a6810b65268241cc0449912bb46c8e0198314".into());
        let secret_key: Option<String> =
            Some("f9eacfff89deb907d55a1a70abd5d0fd6907b96863c4842a4612828122bf5ce0".into());
        let account: FuturesAccount = crate::api::Binance::new_with_config(api_key.clone(), secret_key, &cfg);
        let order = OrderRequest {
            symbol: "BTCUSDT".into(),
            side: OrderSide::Sell,
            position_side: None,
            order_type: OrderType::Limit,
            time_in_force: Some(TimeInForce::GTC),
            quantity: Some(0.01),
            reduce_only: None,
            price: Some(68000.),
            stop_price: None,
            close_position: None,
            activation_price: None,
            callback_rate: None,
            working_type: None,
            price_protect: None,
            new_client_order_id: None,
        };

        let order_2 = OrderRequest {
            symbol: "BTCUSDT".into(),
            side: OrderSide::Buy,
            position_side: None,
            order_type: OrderType::StopMarket,
            time_in_force: Some(TimeInForce::GTC),
            quantity: Some(0.01),
            reduce_only: None,
            price: None,
            stop_price: Some(69000.),
            close_position: None,
            activation_price: None,
            callback_rate: None,
            working_type: None,
            price_protect: None,
            new_client_order_id: None,
        };
        // account.cancel_all_open_orders("btcusdt").await.unwrap();
        // account.place_batch_orders(vec![order, order_2]).await.unwrap();
        let all_order = account.get_open_orders("btcusdt").await.unwrap();

        let mut stop_order: OrderRequest = all_order
            .iter()
            .find(|x| match x.order_type {
                OrderType::Stop | OrderType::StopMarket => true,
                _ => false,
            })
            .cloned()
            .unwrap()
            .into();

        stop_order.stop_price = Some(58000.);
        let symbol = stop_order.symbol.clone();
        let client_id = stop_order.new_client_order_id.clone();
        stop_order.new_client_order_id = None;

        // println!("{:?}", stop_order);
        account.place_order(stop_order).await.unwrap();
        account
            .cancel_order(OrderCancellation {
                symbol,
                order_id: None,
                orig_client_order_id: client_id,
            })
            .await
            .unwrap();

        // account.modify_multiple_orders(vec![stop_order]).await.unwrap();
    }
}
