# VoteEasy: Online Voting System
[![Ask DeepWiki](https://devin.ai/assets/askdeepwiki.png)](https://deepwiki.com/dialga-cmd/voting)

VoteEasy is a full-stack, secure online voting platform designed for organizations and institutions. It features a modern, responsive frontend built with Tailwind CSS and a robust PHP backend powered by a SQLite database. The system includes a comprehensive admin dashboard for managing elections, participants, and viewing real-time results and analytics.

## Features

-   **User Authentication**: Secure user registration and login system with password hashing.
-   **Poll Management**: Admins can create and manage multiple elections or polls, setting titles and start/end dates.
-   **Participant/Candidate Management**: Easily add and remove candidates for each specific poll.
-   **Secure Voting**: Ensures each logged-in user can only cast one vote per election.
-   **Admin Dashboard**: A dedicated dashboard for administrators to get a statistical overview, manage polls, view results, and monitor system activity.
-   **Live Results & Analytics**: View real-time voting results with vote counts and percentage distributions. The analytics section provides insights into participation rates and voting trends.
-   **Responsive UI**: A clean, modern, and fully responsive user interface built with Tailwind CSS, ensuring a seamless experience on both desktop and mobile devices.
-   **System Diagnostics**: Includes backend scripts for system checks and debugging registration issues, aiding developers in setup and maintenance.

## Technology Stack

-   **Frontend**: HTML, JavaScript (ES6+), Tailwind CSS
-   **Backend**: PHP
-   **Database**: SQLite

## Project Structure

The repository is organized with a clear separation between the frontend and backend logic.

```
/
├── index.html            # Main landing page and voting interface
├── poll.html             # (Placeholder) Elections page
├── result.html           # (Placeholder) Results page
├── about.html            # About Us page
├── privacy_policy.html   # Privacy Policy
├── tos.html              # Terms of Service
└── backend/
    ├── admin_dashboard.php # Admin panel for system management
    ├── auth.php            # Handles user login, registration, sessions
    ├── poll.php            # API for managing polls
    ├── participants.php    # API for managing candidates
    ├── submit_vote.php     # API for casting votes
    ├── votes.php           # API for retrieving results and stats
    ├── reset_db.php        # Script to initialize/reset the database
    ├── system_check.php    # Diagnostic tool for developers
    └── voting.db           # SQLite database file
```

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

You need a local server environment with PHP and the SQLite3 extension enabled.
-   PHP >= 7.4
-   SQLite3 PHP Extension

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/dialga-cmd/voting.git
    cd voting
    ```

2.  **Initialize the Database:**
    The project includes a script to set up the SQLite database with the required tables and seed it with default data. Open your web browser and navigate to this script:
    ```
    http://localhost/path/to/your/project/backend/reset_db.php
    ```
    This will delete any existing `voting.db` file and create a new one with sample polls, candidates, and a default admin user.

3.  **Run the application:**
    Start your local PHP server in the root directory of the project.
    ```sh
    php -S localhost:8000
    ```
    You can now access the application at `http://localhost:8000`.

## Usage

### Voter

1.  Open the website in your browser.
2.  Click the "Login" button and then "Register" to create a new account.
3.  Once logged in, an active election will be displayed.
4.  Select an election from the "Active Elections" list.
5.  Choose your preferred candidate from the list by clicking the "Select" button.
6.  Confirm your selection and click "Submit Vote". You will receive a confirmation, and your vote will be securely recorded.

### Administrator

1.  Navigate to the admin dashboard:
    `http://localhost:8000/backend/admin_dashboard.php`

2.  Log in using the default admin credentials created by the `reset_db.php` script:
    -   **Username**: `voteeasy`
    -   **Password**: `admin`

3.  From the dashboard, you can:
    -   Create new polls.
    -   Add or remove participants (candidates) for each poll.
    -   View detailed voting results and analytics.
    -   Monitor recent system activity.
