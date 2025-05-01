# 🍔 WWolt clone

This is a web-based food ordering platform built with **Flask**, **MySQL**, and **mojoCSS**. It supports different user roles (admin, customer, partner, restaurant) and allows restaurants to manage their menu items and profile.

## 🚀 Features

- User authentication and role-based access control
- Restaurant CRUD for menu items (with image uploads)
- Soft-delete of restaurant accounts (with email confirmation)
- Multiple images per item (comma-separated)
- Order confirmation with email notification
- Admin management panel
- Frontend using `mojoCSS` and `mixhtml` (for dynamic interactivity)

## 📦 Requirements

- Python 3.10+
- MySQL 8+
- Flask
- Flask-Session
- mysql-connector-python
- Werkzeug
- Faker (for seeding)
- Redis (if using Redis sessions)
- [mojoCSS](https://mojocss.com)
