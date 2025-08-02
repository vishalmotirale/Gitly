# Gitly 🔍

Gitly is a simple and elegant Flask web app to explore **GitHub repositories** by username, with an option to log in and view **private repositories** using GitHub OAuth.

---

Absolutely! Here's your **Gitly project features** section in the same format:

---

## 🌟 Features

* 🔎 **Search public repositories by GitHub username**
  Easily explore any user's public repositories using their GitHub username.

* 🔐 **GitHub OAuth login to view private repositories**
  Securely sign in with GitHub to access and display your private repositories.

* 🖼️ **Clean and responsive UI (dark themed)**
  Fully responsive, mobile-friendly interface with a sleek dark mode design.

* 🛠️ **Filters for language and minimum stars**
  Instantly filter repositories by programming language and star count.

* 📊 **Real-time repo count and hover effects**
  See the live count of filtered repositories with smooth UI animations and hover highlights.

* 📥 Export repository data
Download filtered repository data as a CSV file for offline analysis or record-keeping.

---

## 🚀 Live Demo

🔗 [https://gitly-bclw.onrender.com]  


---

## 🛠️ Tech Stack

- Python (Flask)
- HTML/CSS/JavaScript
- GitHub OAuth2
- Jinja2 (templating)
- Render (for deployment)

---

## 🔧 Setup Locally

```bash
git clone https://github.com/YOUR_USERNAME/gitly.git
cd gitly
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
