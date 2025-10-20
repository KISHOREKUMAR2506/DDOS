"""
DDoS Detection Model Training Script
Trains a Random Forest classifier for DDoS attack detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

print("🚀 Starting DDoS Model Training...")

# ========== GENERATE TRAINING DATA ==========
print("\n📊 Generating training data...")

# Normal traffic patterns (label = 0)
normal_samples = 5000
normal_data = {
    'packet_count': np.random.randint(1, 50, normal_samples),
    'byte_count': np.random.randint(64, 5000, normal_samples)
}

# DDoS traffic patterns (label = 1)
ddos_samples = 5000

# High packet count attacks
high_packet = {
    'packet_count': np.random.randint(100, 1000, ddos_samples // 2),
    'byte_count': np.random.randint(5000, 100000, ddos_samples // 2)
}

# High byte count attacks
high_byte = {
    'packet_count': np.random.randint(50, 500, ddos_samples // 2),
    'byte_count': np.random.randint(50000, 500000, ddos_samples // 2)
}

# Combine datasets
df_normal = pd.DataFrame(normal_data)
df_normal['label'] = 0

df_ddos_packet = pd.DataFrame(high_packet)
df_ddos_packet['label'] = 1

df_ddos_byte = pd.DataFrame(high_byte)
df_ddos_byte['label'] = 1

df = pd.concat([df_normal, df_ddos_packet, df_ddos_byte], ignore_index=True)

# Shuffle data
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"✅ Generated {len(df)} samples")
print(f"   - Normal traffic: {len(df[df['label']==0])}")
print(f"   - DDoS attacks: {len(df[df['label']==1])}")

# ========== PREPARE DATA ==========
X = df[['packet_count', 'byte_count']]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\n📈 Training set: {len(X_train)} samples")
print(f"📉 Test set: {len(X_test)} samples")

# ========== TRAIN MODEL ==========
print("\n🤖 Training Random Forest classifier...")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("✅ Model training completed")

# ========== EVALUATE MODEL ==========
print("\n📊 Evaluating model performance...")

# Predictions
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"\n🎯 Accuracy: {accuracy*100:.2f}%")

# Classification report
print("\n📋 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal', 'DDoS']))

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
print("\n🔢 Confusion Matrix:")
print(cm)

# Cross-validation
cv_scores = cross_val_score(model, X, y, cv=5)
print(f"\n🔄 Cross-validation scores: {cv_scores}")
print(f"   Average CV score: {cv_scores.mean()*100:.2f}%")

# Feature importance
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print("\n📌 Feature Importance:")
print(feature_importance)

# ========== VISUALIZATIONS ==========
print("\n📊 Generating visualizations...")

# Create figure with subplots
fig, axes = plt.subplots(2, 2, figsize=(15, 12))

# 1. Confusion Matrix Heatmap
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0, 0],
            xticklabels=['Normal', 'DDoS'], yticklabels=['Normal', 'DDoS'])
axes[0, 0].set_title('Confusion Matrix', fontsize=14, fontweight='bold')
axes[0, 0].set_ylabel('True Label')
axes[0, 0].set_xlabel('Predicted Label')

# 2. Feature Importance
axes[0, 1].barh(feature_importance['feature'], feature_importance['importance'], color='skyblue')
axes[0, 1].set_title('Feature Importance', fontsize=14, fontweight='bold')
axes[0, 1].set_xlabel('Importance Score')

# 3. Data Distribution - Packet Count
axes[1, 0].hist([df[df['label']==0]['packet_count'], df[df['label']==1]['packet_count']],
                bins=30, label=['Normal', 'DDoS'], alpha=0.7, color=['green', 'red'])
axes[1, 0].set_title('Packet Count Distribution', fontsize=14, fontweight='bold')
axes[1, 0].set_xlabel('Packet Count')
axes[1, 0].set_ylabel('Frequency')
axes[1, 0].legend()

# 4. Data Distribution - Byte Count
axes[1, 1].hist([df[df['label']==0]['byte_count'], df[df['label']==1]['byte_count']],
                bins=30, label=['Normal', 'DDoS'], alpha=0.7, color=['green', 'red'])
axes[1, 1].set_title('Byte Count Distribution', fontsize=14, fontweight='bold')
axes[1, 1].set_xlabel('Byte Count')
axes[1, 1].set_ylabel('Frequency')
axes[1, 1].legend()

plt.tight_layout()
plt.savefig('model_evaluation.png', dpi=300, bbox_inches='tight')
print("✅ Saved visualization: model_evaluation.png")

# ========== SAVE MODEL ==========
print("\n💾 Saving trained model...")

model_filename = 'ddos_model.pkl'
joblib.dump(model, model_filename)

print(f"✅ Model saved as: {model_filename}")

# ========== TEST PREDICTIONS ==========
print("\n🧪 Testing sample predictions...")

test_samples = pd.DataFrame([
    {'packet_count': 10, 'byte_count': 500},      # Normal
    {'packet_count': 500, 'byte_count': 50000},   # DDoS
    {'packet_count': 25, 'byte_count': 1500},     # Normal
    {'packet_count': 800, 'byte_count': 80000},   # DDoS
])

predictions = model.predict(test_samples)
probabilities = model.predict_proba(test_samples)

print("\n🔍 Sample Predictions:")
for i, (idx, row) in enumerate(test_samples.iterrows()):
    pred = "DDoS" if predictions[i] == 1 else "Normal"
    conf = max(probabilities[i]) * 100
    print(f"   Sample {i+1}: packets={row['packet_count']}, bytes={row['byte_count']}")
    print(f"   → Prediction: {pred} (Confidence: {conf:.1f}%)")

# ========== SAVE TRAINING DATA ==========
print("\n💾 Saving training data for reference...")

df.to_csv('training_data.csv', index=False)
print("✅ Saved: training_data.csv")

# ========== MODEL INFO ==========
print("\n" + "="*50)
print("MODEL TRAINING SUMMARY")
print("="*50)
print(f"Model Type: Random Forest Classifier")
print(f"Number of Trees: {model.n_estimators}")
print(f"Training Samples: {len(X_train)}")
print(f"Test Samples: {len(X_test)}")
print(f"Accuracy: {accuracy*100:.2f}%")
print(f"Cross-Val Score: {cv_scores.mean()*100:.2f}%")
print(f"Features: {list(X.columns)}")
print(f"Model File: {model_filename}")
print("="*50)

print("\n✅ Model training completed successfully!")
print("🚀 You can now use 'ddos_model.pkl' in your Ryu controller")
print("\nTo use the model:")
print("  1. Copy ddos_model.pkl to your project directory")
print("  2. Run: ryu-manager ddos_detector.py")
print("  3. Model will automatically load and start detecting threats")

# ========== EXPORT MODEL METADATA ==========
model_metadata = {
    'model_type': 'RandomForestClassifier',
    'n_estimators': model.n_estimators,
    'accuracy': float(accuracy),
    'cv_score': float(cv_scores.mean()),
    'features': list(X.columns),
    'training_samples': len(X_train),
    'test_samples': len(X_test),
    'normal_threshold': {
        'packet_count_max': int(df[df['label']==0]['packet_count'].max()),
        'byte_count_max': int(df[df['label']==0]['byte_count'].max())
    },
    'ddos_threshold': {
        'packet_count_min': int(df[df['label']==1]['packet_count'].min()),
        'byte_count_min': int(df[df['label']==1]['byte_count'].min())
    }
}

import json
with open('model_metadata.json', 'w') as f:
    json.dump(model_metadata, f, indent=4)

print("✅ Saved: model_metadata.json")
print("\n🎉 Training complete! Ready for deployment.")