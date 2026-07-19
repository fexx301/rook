pub mod blog;

use askama::Template;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::config::PersonaConfig;
use crate::server::AppState;
use crate::store::Session;
use crate::traps::TrapContext;
use blog::BlogPost;

/// Render an Askama template into an axum HTML `Response`.
pub struct HtmlTemplate<T>(pub T);

impl<T: Template> IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => (
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                html,
            )
                .into_response(),
            Err(e) => {
                tracing::error!("template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Context shared by every page (brand, honeypot link, trap fragments).
pub struct BaseContext<'a> {
    pub persona_name: &'a str,
    pub tagline: &'a str,
    pub honeypot_url: String,
    pub trap: &'a TrapContext,
}

#[derive(Template)]
#[template(path = "landing.html")]
pub struct LandingTemplate<'a> {
    base: BaseContext<'a>,
    tagline: &'a str,
}

#[derive(Template)]
#[template(path = "blog_index.html")]
pub struct BlogIndexTemplate<'a> {
    base: BaseContext<'a>,
    posts: &'a [BlogPost],
}

#[derive(Template)]
#[template(path = "post.html")]
pub struct PostTemplate<'a> {
    base: BaseContext<'a>,
    post: &'a BlogPost,
}

#[derive(Template)]
#[template(path = "simple.html")]
pub struct SimpleTemplate<'a> {
    base: BaseContext<'a>,
    title: &'a str,
    body: &'a str,
}

fn base_context<'a>(
    persona: &'a PersonaConfig,
    session: &'a Session,
    trap: &'a TrapContext,
) -> BaseContext<'a> {
    BaseContext {
        persona_name: &persona.name,
        tagline: &persona.tagline,
        honeypot_url: format!("/h/{}", session.honeypot_token),
        trap,
    }
}

pub async fn landing(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<Session>,
) -> Response {
    let trap = TrapContext::build(&session);
    HtmlTemplate(LandingTemplate {
        base: base_context(&state.config.persona, &session, &trap),
        tagline: &state.config.persona.tagline,
    })
    .into_response()
}

pub async fn blog_index(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<Session>,
) -> Response {
    let posts: Vec<_> = blog::posts()
        .into_iter()
        .take(state.config.persona.blog_posts)
        .collect();
    let trap = TrapContext::build(&session);
    HtmlTemplate(BlogIndexTemplate {
        base: base_context(&state.config.persona, &session, &trap),
        posts: &posts,
    })
    .into_response()
}

pub async fn blog_post(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<Session>,
    Path(slug): Path<String>,
) -> Response {
    let trap = TrapContext::build(&session);
    match blog::get_post(&slug, state.config.persona.blog_posts) {
        Some(post) => HtmlTemplate(PostTemplate {
            base: base_context(&state.config.persona, &session, &trap),
            post: &post,
        })
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn docs(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<Session>,
) -> Response {
    let trap = TrapContext::build(&session);
    HtmlTemplate(SimpleTemplate {
        base: base_context(&state.config.persona, &session, &trap),
        title: "Docs",
        body: "<p>Documentation is being written. Check back soon!</p>",
    })
    .into_response()
}

pub async fn pricing(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<Session>,
) -> Response {
    let trap = TrapContext::build(&session);
    HtmlTemplate(SimpleTemplate {
        base: base_context(&state.config.persona, &session, &trap),
        title: "Pricing",
        body: "<p>Pricing plans will be announced soon. Stay tuned.</p>",
    })
    .into_response()
}

pub async fn robots_txt(State(state): State<Arc<AppState>>) -> Response {
    let body = format!(
        "User-agent: *\nAllow: /\nSitemap: https://{}/sitemap.xml\n",
        state.config.persona.domain
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub async fn sitemap_xml(State(state): State<Arc<AppState>>) -> Response {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    let domain = &state.config.persona.domain;
    body.push_str(&format!("  <url><loc>https://{}/</loc></url>\n", domain));
    body.push_str(&format!(
        "  <url><loc>https://{}/blog</loc></url>\n",
        domain
    ));
    for post in blog::posts()
        .into_iter()
        .take(state.config.persona.blog_posts)
    {
        body.push_str(&format!(
            "  <url><loc>https://{}/blog/{}</loc></url>\n",
            domain, post.slug
        ));
    }
    body.push_str("</urlset>\n");
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/xml; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// Explicit trap routes return an ordinary 404 after the session middleware
/// records the visit and its corresponding signal.
pub async fn honeypot() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Unknown paths are still passed through the detection middleware so a
/// canary exfiltrated into an arbitrary URL can be caught.
pub async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

pub async fn favicon() -> Response {
    // Transparent 1x1 GIF pixel — keeps browsers happy, no logo file needed.
    (
        [(axum::http::header::CONTENT_TYPE, "image/gif")],
        axum::body::Bytes::from_static(&[
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3b,
        ]),
    )
        .into_response()
}
