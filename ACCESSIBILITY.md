# Accessibility

Authority aims to be accessible to everyone, including the documentation site and the library itself.

## Documentation site

- **Color contrast**: The default Material for MkDocs theme is designed to meet WCAG AA contrast ratios. Custom colors in `docs/stylesheets/extra.css` are chosen to maintain sufficient contrast.
- **Text scaling**: Pages are fully readable when zoomed and use relative font sizing.
- **Keyboard navigation**: All navigation elements are operable via the keyboard.
- **Images**: Screenshots in the documentation are accompanied by descriptive alt text.
- **Semantic HTML**: The generated site uses proper heading hierarchy, landmarks, and link text.

## Library

- **Inclusive defaults**: Configuration defaults avoid hard-coded UI-facing language where possible.
- **Clear errors**: Exceptions carry descriptive, actionable messages (see `docs/troubleshooting.md`).
- **Environment-first configuration**: Secrets are read from environment variables, which works with accessible deployment tooling.

## Reporting accessibility issues

If you find an accessibility problem in the documentation site or the library, please open a GitHub issue at <https://github.com/rkriad585/authority/issues> and include:

- The URL or page where the problem occurs
- A description of the issue
- The assistive technology or browser configuration you were using
- How to reproduce the problem

We treat accessibility issues as bugs and will address them in a timely manner.
