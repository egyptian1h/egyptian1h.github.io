---
title: "Getting Started with Jekyll & Chirpy: A Beginner's Guide"
date: 2026-03-28 12:00:00 +0200
categories: [Tech, Web Development]
tags: [jekyll, chirpy, blogging, github-pages, tutorial]
---

## What is Jekyll?

**Jekyll** is a static site generator — it takes your plain text (Markdown files) and turns them into a fully-featured website. No database. No server-side code. Just fast, clean HTML.

It is the engine behind thousands of developer blogs, and it powers this site.

## Why Chirpy?

There are dozens of Jekyll themes out there, but **Chirpy** stands out for a few reasons:

- Clean, modern design — dark/light mode, responsive layout
- Table of Contents — auto-generated for every post
- Full-text search — built right in
- Tags & Categories — organize your content effortlessly
- Fast — static files served over GitHub Pages CDN

## Setting Up Your Blog in 5 Minutes

### 1. Use the Chirpy Starter Template

Go to `https://github.com/cotes2020/chirpy-starter`, click **Use this template**, and name it `yourusername.github.io`.

### 2. Configure `_config.yml`

```yaml
title: My Awesome Blog
url: "https://yourusername.github.io"
github:
  username: yourusername
social:
  name: Your Name
  email: you@example.com
```

### 3. Write Your First Post

Create a file in `_posts/` named `YYYY-MM-DD-your-title.md`:

```markdown
---
title: "My First Post"
date: 2026-03-28 12:00:00 +0200
categories: [General]
tags: [hello, world]
---

Hello, world! This is my first blog post.
```

### 4. Push and Deploy

GitHub Actions builds and deploys to GitHub Pages automatically on every push. No manual steps needed.

## Tips for Writing Great Posts

| Tip | Why It Matters |
|-----|---------------|
| Use headers (##, ###) | Improves readability + auto-generates TOC |
| Add code blocks | Chirpy has beautiful syntax highlighting |
| Use tags & categories | Makes content discoverable |
| Keep URLs short | Better for SEO and sharing |

## Final Thoughts

Static blogs are **fast**, **free** (thanks to GitHub Pages), and **easy to maintain**. With Chirpy, you get a professional-looking site with zero design effort — so you can focus on what matters: **writing**.

Happy blogging!

---

*This blog is built with Jekyll and the Chirpy theme, hosted on GitHub Pages.*
