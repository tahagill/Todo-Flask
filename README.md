# To-Do App

This is a basic To-Do application built with **Flask** for the backend, **SQLite3** for the database, and **HTML/CSS** for the frontend. It allows users to create, read, update, and delete tasks. The app is designed to help you manage your daily tasks efficiently with a simple and intuitive interface.

## 🛠️ Tech Stack

- **Backend:** Flask (Python)
- **Frontend:** HTML, CSS
- **Database:** SQLite3
- **Authentication:** (Basic)

## 📦 Features

- **Create Tasks:** Add new tasks to the to-do list.
- **Read Tasks:** View your current tasks.
- **Update Tasks:** Mark tasks as completed or edit their details.
- **Delete Tasks:** Remove tasks from the list.
- Simple and responsive frontend using HTML and CSS.

## 🚀 Setup & Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/tahagill/Todo-Flask.git
    cd Todo-Flask
    ```

2. **Create a virtual environment & activate it:**

    ```bash
    python -m venv env
    # On Windows:
    env\Scripts\activate
    # On macOS/Linux:
    source env/bin/activate
    ```

3. **Install the required dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Set up the SQLite database:**

    The database is automatically created when the app runs for the first time. If you prefer, you can manually set it up using:

    ```bash
    python
    >>> from app import db
    >>> db.create_all()
    ```

5. **Run the server:**

    ```bash
    python app.py
    ```

6. **Access the app in your browser:**

    Go to [http://127.0.0.1:5000/](http://127.0.0.1:5000/) to view the app.



