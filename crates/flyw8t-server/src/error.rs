use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Errors a request handler can return. Internal details are logged, never shown.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("you are not allowed to do that")]
    Forbidden,
    #[error("sign in required")]
    Unauthorized,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("too many attempts; wait a minute and try again")]
    RateLimited,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::BadRequest(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn log(&self) {
        if let AppError::Internal(e) = self {
            tracing::error!(error = %format!("{e:#}"), "request failed");
        }
    }
}

/// JSON rendering, for the API.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.log();
        let body = serde_json::json!({ "error": self.to_string() });
        (self.status(), axum::Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
