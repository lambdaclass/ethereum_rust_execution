use std::{any::Any, time::Duration};

use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    handler::Handler,
    http::{header, Response, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde_json::Value;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tracing::error;

use crate::utils::{rpc_response, RpcErr};

pub fn rpc_router<H, T, S>(handler: H, storage: S) -> Router
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    let router: Router = Router::new()
        .route("/", post(handler))
        .with_state(storage)
        .layer(
            ServiceBuilder::new()
                .layer(CatchPanicLayer::custom(handle_panic))
                .layer(HandleErrorLayer::new(handle_error))
                .timeout(Duration::from_secs(30)), // .into_inner(),
        );

    router
}

fn handle_panic(error: Box<dyn Any + Send + 'static>) -> Response<Body> {
    let details = if let Some(s) = error.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = error.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic message".to_string()
    };
    error!("Request panic: {}", details);

    let body = rpc_response(0, Err::<Value, _>(RpcErr::Internal));

    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn handle_error(error: Box<dyn std::error::Error + Send + Sync>) -> impl IntoResponse {
    error!("Request failed: {}", error);
    rpc_response(0, Err::<Value, _>(RpcErr::Internal))
}
