from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pandas as pd
import joblib

data = pd.read_csv("ipv6_dataset.csv")
X = data[['packet_count','byte_count']]
y = data['label']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

model = DecisionTreeClassifier(random_state=42)
model.fit(X_train, y_train)

print("✅ Model Evaluation:")
print(classification_report(y_test, model.predict(X_test)))

joblib.dump(model, "ddos_model.pkl")
print("✅ Model saved as ddos_model.pkl")
