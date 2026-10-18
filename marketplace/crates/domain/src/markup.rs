//! Listing markup renderer (spec §9): paragraphs, bullet lists, and bold —
//! nothing else. All input is HTML-escaped first; markup is applied to the
//! escaped text, so no seller input can ever become a tag, attribute, or
//! link. URLs render as plain text.

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// **bold** pairs on escaped text; an unmatched ** is left literal.
fn bold(escaped: &str) -> String {
    let mut out = String::new();
    let mut rest = escaped;
    loop {
        match rest.find("**") {
            None => {
                out.push_str(rest);
                break;
            }
            Some(i) => {
                let after = &rest[i + 2..];
                match after.find("**") {
                    Some(j) if j > 0 => {
                        out.push_str(&rest[..i]);
                        out.push_str("<strong>");
                        out.push_str(&after[..j]);
                        out.push_str("</strong>");
                        rest = &after[j + 2..];
                    }
                    _ => {
                        out.push_str(rest);
                        break;
                    }
                }
            }
        }
    }
    out
}

pub fn render_listing_markup(input: &str) -> String {
    let mut html = String::new();
    let mut paragraph: Vec<String> = Vec::new();
    let mut list: Vec<String> = Vec::new();
    let flush_p = |html: &mut String, p: &mut Vec<String>| {
        if !p.is_empty() {
            html.push_str("<p>");
            html.push_str(&p.join(" "));
            html.push_str("</p>");
            p.clear();
        }
    };
    let flush_l = |html: &mut String, l: &mut Vec<String>| {
        if !l.is_empty() {
            html.push_str("<ul>");
            for item in l.drain(..) {
                html.push_str("<li>");
                html.push_str(&item);
                html.push_str("</li>");
            }
            html.push_str("</ul>");
        }
    };
    for line in input.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            flush_p(&mut html, &mut paragraph);
            flush_l(&mut html, &mut list);
        } else if let Some(item) = line.strip_prefix("- ") {
            flush_p(&mut html, &mut paragraph);
            list.push(bold(&esc(item.trim())));
        } else {
            flush_l(&mut html, &mut list);
            paragraph.push(bold(&esc(line.trim())));
        }
    }
    flush_p(&mut html, &mut paragraph);
    flush_l(&mut html, &mut list);
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paragraphs_lists_bold() {
        let out = render_listing_markup("Hello **world**\nsecond line\n\n- one\n- two **b**\n\nTail");
        assert_eq!(
            out,
            "<p>Hello <strong>world</strong> second line</p><ul><li>one</li><li>two <strong>b</strong></li></ul><p>Tail</p>"
        );
    }

    #[test]
    fn html_is_never_markup() {
        let out = render_listing_markup("<script>alert(1)</script> https://x.example/?a=1&b=2");
        assert!(!out.contains("<script"));
        assert!(!out.contains("<a "));
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("a=1&amp;b=2"));
    }

    #[test]
    fn unmatched_bold_stays_literal() {
        assert_eq!(render_listing_markup("a ** b"), "<p>a ** b</p>");
        assert_eq!(render_listing_markup("****"), "<p>****</p>");
    }
}
