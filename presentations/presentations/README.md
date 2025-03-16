# Presentation Setup

This directory contains the demo and pitch deck presentation for the LAWFULLY_FLARE project. The presentation is built using [Reveal.js](https://revealjs.com/) and can be viewed locally or deployed to a public URL.

## Running the Presentation Locally

1. Navigate to the `presentations` directory:
   ```bash
   cd presentations
   ```

2. Start a local server:
   ```bash
   python3 -m http.server 8000
   ```

3. Open your browser and visit:
   http://localhost:8000

## Deploying the Presentation to a Public URL

To deploy the presentation so it can be accessed by your team:

1. Use a service like [Vercel](https://vercel.com), [Netlify](https://www.netlify.com), or [GitHub Pages](https://pages.github.com).

2. Deploy the entire `presentations` directory as a static site.

3. Share the public URL provided by the hosting service.

## Customizing the Presentation

- **Content**: Edit the `index.html` file to update the slides with your desired content.
- **Styling**: Modify the `css/style.css` file to adjust colors, fonts, and layout to match your branding.
- **Features**: Explore the [Reveal.js documentation](https://revealjs.com/) for advanced features like animations, transitions, and plugins.

