# API Security Design Wizard 🛡️
### API Threat Modelling & AuthN/Z Decision Engine
*Built by **cyberbali***

API Security Design Wizard is a standalone, client-side interactive web application designed to guide software architects, developers, and security engineers through a structured, phased threat modelling and authentication/authorization decision tree framework. 

By answering a series of environmental and business questions, API Security Design Wizard dynamically computes threat complexity scores, evaluates caller-specific decision trees, maps appropriate access control dimensions, and generates a comprehensive, print-ready **Security Architecture Design Document** containing targeted mitigations and robust architectural specifications.

---

## 🚀 Key Features

* **Phased Security Framework**: Operationalizes the 5-phase threat modelling and auth decision tree methodology (Threat Profile, AuthN Decision Paths, AuthZ Dimension Mapping, Cross-Cutting concerns, and Failure Modes).
* **Mixed Caller Multi-Branch Walking**: Real-world APIs support multiple calling interfaces. If you select multiple caller types (e.g. Browser + Machine-to-Machine), the engine dynamically routes you through the AuthN decision tree *once per caller*, consolidating custom recommendations.
* **100% Client-Side & Private**: All state processing, questionnaire evaluation, SVG generation, and document compile flows run entirely inside the user's browser. **No data is sent to external servers, no databases are required, and no trackers or secrets are embedded.**
* **Dynamic Middlewares Flowchart**: Renders a custom vector-based SVG Request Flow diagram showing how Layer 1 (AuthN), Layer 2 (Coarse AuthZ), and Layer 3 (Fine AuthZ) interface before querying scoped database data.
* **Robust Document Exports**: Copy raw Markdown with one-click, download it as a `.md` file, or print/save as a beautifully formatted PDF using custom print-specific CSS stylesheets.

---

## 🛠️ How to Run Locally

Because API Security Design Wizard leverages modern ES6 Modules (`type="module"`), browsers restrict loading files directly via the `file://` protocol due to CORS safety constraints. You must host the files using a lightweight local web server.

### Option 1: Python HTTP Server (Zero Dependencies)
If you have Python installed, navigate to the project directory in your terminal and run:
```bash
python -m http.server 8000
```
Open your browser and navigate to: **[http://localhost:8000](http://localhost:8000)**

### Option 2: Vite Dev Server (NPM)
If you prefer standard JavaScript tooling:
```bash
npm install
npm run dev
```
Open your browser and navigate to the address output by Vite (typically `http://localhost:5173`).

---

## 🌐 How to Deploy to GitHub Pages (2-Minute Hosting)

API Security Design Wizard is a fully static application, making it perfect for **GitHub Pages** hosting at zero cost and with zero setup hassle!

1. Create a new repository on GitHub and commit this codebase to the `main` branch.
2. In your repository on GitHub, navigate to **Settings** $\rightarrow$ **Pages**.
3. Under **Build and deployment**, set **Source** to `Deploy from a branch`.
4. Select the `main` branch and the `/ (root)` folder, then click **Save**.
5. After a few seconds, GitHub will output a public hosting URL (e.g., `https://yourusername.github.io/your-repo-name`).

*No build steps, no databases, and no configuration required!*

---

## 📄 License & Credits

* Developed by [cyberbali](https://cyberbali.in).
* Concept derived from industry-standard API threat modeling decision trees and modern access control principles (RBAC, ABAC, ReBAC, and Hybrid strategies).
