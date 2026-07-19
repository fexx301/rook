pub struct BlogPost {
    pub slug: String,
    pub title: String,
    pub date: String,
    pub author: String,
    pub excerpt: String,
    pub body: String,
}

pub fn posts() -> Vec<BlogPost> {
    vec![
        BlogPost {
            slug: "introducing-frameshift".to_string(),
            title: "Introducing FrameShift".to_string(),
            date: "2026-01-15".to_string(),
            author: "Alex Chen".to_string(),
            excerpt: "Today we're launching FrameShift, a suite of developer tools built in Rust that prioritize speed, privacy, and extensibility.".to_string(),
            body: r#"<p>We've been building developer tools for years, and we kept running into the same problems: tools that were slow, tools that sent your code to the cloud, and tools that couldn't be customized. So we decided to build something different.</p>
            <p>FrameShift is a suite of developer tools built entirely in Rust. It's fast, it's local-first, and it's extensible through a powerful plugin system.</p>
            <h2>Why Rust?</h2>
            <p>We chose Rust for three reasons: performance, safety, and ergonomics. Rust gives us the speed of C without the memory safety issues, and the expressiveness of modern languages without the runtime overhead.</p>
            <p>When you're running a tool on every keystroke, every millisecond counts. Rust's zero-cost abstractions let us write clean, high-level code that compiles down to machine code that's competitive with hand-optimized C.</p>
            <h2>What's next?</h2>
            <p>Over the coming months we'll be releasing plugins for popular editors, CLI tools, and CI integrations. Sign up for our newsletter to stay in the loop.</p>"#.to_string(),
        },
        BlogPost {
            slug: "plugin-system-in-rust".to_string(),
            title: "Building FrameShift's Plugin System in Rust".to_string(),
            date: "2026-02-03".to_string(),
            author: "Sam Rivera".to_string(),
            excerpt: "A deep dive into how we designed a safe, sandboxed plugin system using WebAssembly and dynamic linking.".to_string(),
            body: r#"<p>One of the core ideas behind FrameShift is that your tools should adapt to your workflow, not the other way around. That's why we built a plugin system from day one.</p>
            <h2>WebAssembly plugins</h2>
            <p>For plugins that need to run arbitrary logic, we use WebAssembly. This gives us a few key properties:</p>
            <ul>
                <li><strong>Sandboxed execution.</strong> A plugin can't read files you haven't given it access to.</li>
                <li><strong>Language agnostic.</strong> Plugin authors can write in Rust, Go, TypeScript, or anything that compiles to WASM.</li>
                <li><strong>Portable binaries.</strong> A single <code>.wasm</code> file runs on every platform FrameShift supports.</li>
            </ul>
            <h2>Native hooks</h2>
            <p>For plugins that need maximum performance, we expose a small, stable C ABI. Native plugins are still loaded in a restricted process, but they can talk to the host through a well-defined message protocol.</p>
            <pre><code>#[frameshift::plugin]
fn on_save(ctx: &mut Context, file: &Path) {
    ctx.run_formatter(file);
}</code></pre>
            <p>The <code>#[frameshift::plugin]</code> macro handles all the boilerplate so authors can focus on their logic.</p>"#.to_string(),
        },
        BlogPost {
            slug: "local-first-tools".to_string(),
            title: "The Case for Local-First Developer Tools".to_string(),
            date: "2026-02-28".to_string(),
            author: "Morgan Lee".to_string(),
            excerpt: "Why we believe the best developer tools run on your machine, not someone else's.".to_string(),
            body: r#"<p>For the last decade, the default assumption in software has been "cloud-first." Your code lives in the cloud, your tools run in the cloud, and your data is analyzed in the cloud. We think that's backwards for developer tools.</p>
            <h2>Latency matters</h2>
            <p>When you press a key, you want feedback in milliseconds, not tens of milliseconds. Every network roundtrip introduces jitter that breaks flow state. Local tools win on latency by definition.</p>
            <h2>Privacy and ownership</h2>
            <p>Your source code is your intellectual property. Sending it to a remote service for formatting, linting, or analysis creates unnecessary risk. Local-first tools keep your code on your machine.</p>
            <h2>Offline resilience</h2>
            <p>Planes, trains, and coffee shops with spotty Wi-Fi shouldn't break your workflow. Local tools work everywhere.</p>
            <p>FrameShift is designed around these principles. Every feature we build asks: can this run locally?</p>"#.to_string(),
        },
        BlogPost {
            slug: "frameshift-2-whats-new".to_string(),
            title: "FrameShift 2.0: What's New".to_string(),
            date: "2026-03-20".to_string(),
            author: "Alex Chen".to_string(),
            excerpt: "Our biggest release yet: a rewritten engine, new plugins, and deeper editor integrations.".to_string(),
            body: r#"<p>Today we're shipping FrameShift 2.0. This release represents a year of engineering work and thousands of commits from our team.</p>
            <h2>Engine rewrite</h2>
            <p>The core engine has been rewritten to use a streaming architecture. For large codebases, this means startup times are down by 60% and memory usage is cut in half.</p>
            <h2>New plugin marketplace</h2>
            <p>You can now browse, install, and update plugins without leaving your editor. Every plugin is cryptographically signed and verified before installation.</p>
            <h2>Editor integrations</h2>
            <p>We've added first-class support for VS Code, Zed, Neovim, and Emacs. More editors are on the way.</p>
            <h2>Get the update</h2>
            <p>If you're already using FrameShift, run <code>frameshift update</code>. If you're new, head to the <a href="/docs">docs</a> to get started.</p>"#.to_string(),
        },
        // <MORE_POSTS>
    ]
}

pub fn get_post(slug: &str, limit: usize) -> Option<BlogPost> {
    posts().into_iter().take(limit).find(|p| p.slug == slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_lookup_respects_the_configured_limit() {
        assert!(get_post("introducing-frameshift", 1).is_some());
        assert!(get_post("frameshift-2-whats-new", 1).is_none());
    }
}
