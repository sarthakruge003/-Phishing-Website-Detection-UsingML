import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import pickle
import re
import matplotlib.pyplot as plt
import seaborn as sns

# Function to extract features from URLs
def extract_features(url):
    """
    Extracts features from a URL for phishing detection.
    Features include the presence of short URLs, length of URL, and special character counts.

    Parameters:
    url (str): The URL to analyze.

    Returns:
    dict: A dictionary of extracted features.
    """
    short_url_regex = r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd"
    features = {
        "short_url": int(bool(re.search(short_url_regex, url))),
        "url_length": len(url),
        "special_char_count": sum(1 for char in url if char in ['@', '?', '-', '=', '.', '_', '&', '%', '/', '#', '~', '+', '$', ',']),
        "digit_count": sum(1 for char in url if char.isdigit()),
    }
    return features

# Function to apply feature extraction to the dataset
def process_dataset(data):
    """
    Applies feature extraction to all URLs in the dataset.

    Parameters:
    data (pd.DataFrame): The input dataset with a 'url' column.

    Returns:
    pd.DataFrame: Processed dataset with extracted features.
    """
    features_list = [extract_features(url) for url in data['url']]
    features_df = pd.DataFrame(features_list)
    return features_df

# Load the dataset
# Replace 'phishing_urls.csv' with the actual path to your dataset
data_path = 'dataset.csv'
dataset = pd.read_csv(data_path)

# Ensure the dataset has the required columns
if 'url' not in dataset.columns or 'label' not in dataset.columns:
    raise ValueError("The dataset must contain 'url' and 'label' columns.")

# Process the dataset to extract features
print("Extracting features from URLs...")
X = process_dataset(dataset)  # Features
y = dataset['label']  # Target

# Standardize the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split the dataset into training and testing sets
print("Splitting the dataset into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Train a Logistic Regression model
print("Training the Logistic Regression model...")
model = LogisticRegression(max_iter=1000, solver='lbfgs')
model.fit(X_train, y_train)

# Evaluate the model
print("Evaluating the model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")
print("Classification Report:")
print(classification_report(y_test, y_pred))

# Confusion Matrix Visualization
conf_matrix = confusion_matrix(y_test, y_pred)
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=['Legitimate', 'Phishing'], yticklabels=['Legitimate', 'Phishing'])
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# Save the trained model and scaler
model_file_path = 'phishing_detection_model.pkl'
scaler_file_path = 'scaler.pkl'
with open(model_file_path, 'wb') as model_file:
    pickle.dump(model, model_file)
with open(scaler_file_path, 'wb') as scaler_file:
    pickle.dump(scaler, scaler_file)
print(f"Model saved to {model_file_path}")
print(f"Scaler saved to {scaler_file_path}")

# Example test for feature extraction
example_url = "https://bit.ly/example"
example_features = extract_features(example_url)
example_features_scaled = scaler.transform(pd.DataFrame([example_features]))
print("Example feature extraction:")
print(example_features)

# Example of loading and using the model
print("Loading the saved model for testing...")
with open(model_file_path, 'rb') as model_file:
    loaded_model = pickle.load(model_file)
prediction = loaded_model.predict(example_features_scaled)
print(f"Prediction for {example_url}: {'Phishing' if prediction[0] == 1 else 'Legitimate'}")