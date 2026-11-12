# Landing page

The bxplore website: plain HTML, CSS and JavaScript, with no build tools or dependencies.

| File | Contents |
| --- | --- |
| `index.html` | The page |
| `style.css` | Styles; dark and light themes use the custom properties at the top |
| `main.js` | Theme toggle, screenshot gallery, lightbox, install tabs, copy buttons, and the download picker: it detects the OS and CPU, reads the latest release from the GitHub API, links the Download button to the matching file and lists every file per platform. Without the API it falls back to the releases page |
| `build.sh` | Assembles `_site/` and checks every referenced asset exists |

The screenshots and icon are not duplicated here. `build.sh` copies them from
`docs/screenshots/` and `packaging/icons/bxplore.svg`, so updating a screenshot
for the README also updates the site.

Preview locally:

    site/build.sh
    python3 -m http.server -d _site    # http://localhost:8000

`.github/workflows/pages.yml` deploys to GitHub Pages on a push to `main` that
touches `site/`, the screenshots, the icon or the workflow (pull requests only
build). Set Settings > Pages > Source to "GitHub Actions" once.
