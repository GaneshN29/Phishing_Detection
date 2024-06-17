**Phishing Detection Flask Server**

This repository contains the code, reports, datasets, and deployment details for a Flask server that detects phishing websites.

**Project Structure:**

* `app.py`: The core Flask application file containing the server logic and API endpoint.
* `models`: Folder containing Python files for your phishing detection model implementation (e.g., `model.py`).
* `reports` (optional): Folder containing any generated reports on model performance or phishing trends.
* `datasets`: Folder housing the datasets used for training and validating your model:
    * `mendeley_dataset_full.csv`: The CSV file containing data used to train your model.
    * `dataset_phishing.csv`: The CSV file containing data used to validate your model during hyperparameter tuning.
* `requirements.txt`: Lists the Python dependencies required to run the server.
* `README.md` (this file): Provides an overview of the project, deployment, and usage instructions.

**Deployment:**

The server is currently hosted on:

* URL: [https://phishing-detection-wrz8.onrender.com](https://phishing-detection-wrz8.onrender.com)

**API Endpoint:**

The server exposes an API endpoint for making phishing detection predictions:

* Endpoint: [https://phishing-detection-wrz8.onrender.com/predict](https://phishing-detection-wrz8.onrender.com/predict)

**Usage:**

**Prerequisites:**

- Ensure you have Python (version 3.x recommended) and pip (the package installer) installed on your system. You can verify this by running `python --version` and `pip --version` in your terminal.
   - If not installed, download them from [https://www.python.org/downloads/](https://www.python.org/downloads/).

**Set up the Development Environment:**

1. Create a virtual environment to isolate project dependencies (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # For Linux/macOS
   venv\Scripts\activate.bat  # For Windows
   ```
2. Install the required dependencies from `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

**Run the Server:**

1. Navigate to the project directory in your terminal.
2. Start the server using Flask's built-in development server:
   ```bash
   python app.py
   ```
   - The server will typically run on `http://127.0.0.1:5000/` (replace with your machine's IP address if accessing remotely). You can verify this in your web browser.

**Making Predictions:**

The server's API endpoint now expects a JSON request body with an array of URLs to be classified:

```json
{
  "urls": ["http://www.crestonwood.com/router.php","http://www.example.com"]
}
```

Example using `curl` (replace with your preferred HTTP client library):

```bash
curl -X POST -H "Content-Type: application/json" -d '{"urls": ["http://www.crestonwood.com/router.php", "http://www.example.com"]}' https://phishing-detection-wrz8.onrender.com/predict

```

The response will be a JSON object indicating the predicted class (phishing or legitimate) and a confidence score (probability).

**Additional Notes:**

- For production use, consider deploying the server using a more robust web server like Gunicorn or uWSGI.
- Regularly update the model with fresh training data to maintain accuracy.
- Implement security measures (authentication, authorization) if the API is exposed publicly.

**Code:**

- Specific code examples are intentionally omitted to avoid cluttering the README. However, the `models` folder contains the Python files for your model implementation. Refer to these files for the core logic of your phishing detection model.

**Reports and Datasets (Optional):**

- The `reports` folder may contain generated reports on model performance or phishing trends (e.g., `training_report.pdf`). These reports can provide insights into the model's training process and effectiveness.
- The `datasets` folder houses the CSV files used for training and validation:
    * `mendeley_dataset_full.csv`: This file contains features and labels used to train your model.
    * `dataset_phishing.csv`: The CSV file containing data used to validate your model during hyperparameter tuning.