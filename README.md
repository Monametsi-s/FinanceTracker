<<<<<<< HEAD
# Finance Tracker

## 🚀 Overview
Finance Tracker is a full-stack web application that allows users to track their expenses, categorize spending, and gain insights into their financial habits. Built with **React (Vite) for the frontend**, **FastAPI for the backend**, and **PostgreSQL for data storage**, this app ensures a smooth and efficient experience.

## 🛠️ Tech Stack
- **Frontend:** React (Vite) + Tailwind CSS
- **Backend:** FastAPI (Python) + SQLAlchemy
- **Database:** PostgreSQL
- **Authentication:** JWT-based authentication
- **Hosting (Optional):** Vercel (Frontend), Render/Fly.io (Backend & DB)

## ✨ Features
- 🔐 **User Authentication** (Register/Login with JWT)
- 📊 **Expense Tracking** (Add, Edit, Delete expenses)
- 🏷️ **Category-based Expense Filtering**
- 📈 **Spending Insights** (Charts & Graphs)
- 📂 **Export Reports** (Download expenses in CSV format)

## 🚀 Getting Started

### 1️⃣ Clone the Repository
```sh
git clone https://github.com/Monametsi-s/finance-tracker.git
cd finance-tracker
```

### 2️⃣ Backend Setup (FastAPI)
#### Install dependencies:
```sh
cd backend
python -m venv venv
source venv/bin/activate   # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
```

#### Set up environment variables:
Create a `.env` file in the backend directory and add:
```
DATABASE_URL=postgresql://username:password@localhost/finance_tracker
SECRET_KEY=your_jwt_secret
```

#### Run migrations:
```sh
alembic upgrade head
```

#### Start FastAPI server:
```sh
uvicorn main:app --reload
```

### 3️⃣ Frontend Setup (React)
#### Install dependencies:
```sh
cd frontend
npm install
```

#### Start the frontend server:
```sh
npm run dev
```

### 4️⃣ Access the App
- **Backend API Docs:** `http://localhost:8000/docs`
- **Frontend:** `http://localhost:5173`

## 📌 API Endpoints
| Method | Endpoint            | Description         |
|--------|--------------------|---------------------|
| POST   | `/auth/register`   | Register a new user |
| POST   | `/auth/login`      | Login and get token |
| GET    | `/expenses`        | Get all expenses |
| POST   | `/expenses`        | Add new expense |
| PUT    | `/expenses/{id}`   | Update an expense |
| DELETE | `/expenses/{id}`   | Delete an expense |

## 🎯 To-Do List
- [ ] Add Income Tracking
- [ ] Implement Recurring Expenses Feature
- [ ] Multi-Currency Support
- [ ] Dark Mode

## 🤝 Contributing
Feel free to submit issues and pull requests! 🚀

## 📜 License
=======
# Horizon Banking Platform

A modern online banking platform built with Next.js, TypeScript, Tailwind CSS, and more.

## Overview

This project is a learning exercise following a tutorial to build a comprehensive online banking platform. It aims to provide users with features such as:

* Connecting external bank accounts
* Viewing account balances and transaction history
* Categorizing spending
* Modern and responsive user interface

This project utilizes the following main technologies:

* **Next.js:** A React framework for building server-rendered and static web applications.
* **TypeScript:** A statically typed superset of JavaScript.
* **Tailwind CSS:** A utility-first CSS framework for rapid UI development.
* **React Hook Form:** For building robust and user-friendly forms.
* **Zod:** For schema declaration and validation.
* **Shadcn UI:** A collection of accessible and reusable UI components built with Radix UI and Tailwind CSS (to be integrated).
* **Plaid:** For securely linking user bank accounts (integration to be implemented).
* **Charts:** For visualizing financial data (library to be chosen and integrated).
* **Sentry:** For error monitoring (integration to be implemented).
* **tailwindcss-animate:** Tailwind CSS plugin for animations.
* **query-string:** For parsing and stringifying URL query parameters.

## Getting Started

Follow these steps to get your local development environment running:

### Prerequisites

* **Node.js:** Make sure you have Node.js (preferably the latest LTS version) installed on your system. You can download it from [https://nodejs.org/](https://nodejs.org/).
* **npm (or yarn or pnpm):** Node.js comes with npm. If you prefer yarn, you can install it with `npm install --global yarn`. If you prefer pnpm, install it with `npm install --global pnpm`.

### Installation

1.  **Clone the repository:** (If you had a previous repository, you don't need to do this if you followed the "start from scratch" steps, as you created a new project). If you were starting from a Git repository, you would run:

    ```bash
    git clone <repository-url>
    cd horizon-banking-platform
    ```

2.  **Install dependencies:** Navigate to the project directory in your terminal and run:

    ```bash
    npm install
    # or
    yarn install
    # or
    pnpm install
    ```

### Running the Development Server

1.  Once the dependencies are installed, start the Next.js development server:

    ```bash
    npm run dev
    # or
    yarn dev
    # or
    pnpm dev
    ```

2.  Open your web browser and navigate to `http://localhost:3000` to view the application.

## Contributing

(Add information about how others can contribute to the project if it's open for collaboration.)

## License

>>>>>>> 15661755ab62f674a92adf04239f52a0a86ac5e8
This project is licensed under the MIT License.

