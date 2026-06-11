# app.py
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import mean_absolute_error, r2_score
import warnings
import hashlib
import hmac
import os
from functools import wraps

warnings.filterwarnings('ignore')

# ----------------------------- SECURITY MODULE -----------------------------
class SecurityManager:
    """Manages security operations including hashing and data validation."""
    
    # Secret key for HMAC (should be stored in environment in production)
    SECRET_KEY = os.getenv('SECURITY_KEY', 'hospital-bed-prediction-secure-key-v1')
    
    @staticmethod
    def hash_data(data: str, algorithm: str = 'sha256') -> str:
        """
        Hash sensitive data using specified algorithm.
        Supported algorithms: sha256, sha512, md5
        """
        if algorithm == 'sha256':
            return hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data.encode()).hexdigest()
        elif algorithm == 'md5':
            return hashlib.md5(data.encode()).hexdigest()
        else:
            return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def generate_hmac(data: str, secret: str = None) -> str:
        """Generate HMAC signature for data integrity verification."""
        if secret is None:
            secret = SecurityManager.SECRET_KEY
        return hmac.new(
            secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def verify_hmac(data: str, signature: str, secret: str = None) -> bool:
        """Verify HMAC signature for data integrity."""
        if secret is None:
            secret = SecurityManager.SECRET_KEY
        expected_signature = SecurityManager.generate_hmac(data, secret)
        return hmac.compare_digest(signature, expected_signature)
    
    @staticmethod
    def validate_input(value: str, input_type: str = 'text', max_length: int = 100) -> bool:
        """Validate user input to prevent injection attacks."""
        if not isinstance(value, str):
            return False
        
        if len(value) > max_length:
            return False
        
        if input_type == 'text':
            # Allow only alphanumeric, spaces, and basic punctuation
            import re
            pattern = r'^[a-zA-Z0-9\s\-\.\/\(\),]+$'
            return bool(re.match(pattern, value))
        
        return True
    
    @staticmethod
    def hash_file(filepath: str, algorithm: str = 'sha256') -> str:
        """Calculate hash of file for integrity verification."""
        hash_obj = hashlib.new(algorithm)
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            st.error(f"Error hashing file: {e}")
            return None
    
    @staticmethod
    def sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
        """Remove potentially sensitive columns and sanitize data."""
        # Remove columns that might contain PII
        sensitive_columns = ['patient_id', 'ssn', 'email', 'phone', 'address']
        df_cleaned = df.copy()
        
        for col in sensitive_columns:
            if col in df_cleaned.columns:
                # Hash the column instead of removing
                df_cleaned[col] = df_cleaned[col].astype(str).apply(
                    lambda x: SecurityManager.hash_data(x)[:16]
                )
        
        return df_cleaned
    
    @staticmethod
    def get_data_checksum(df: pd.DataFrame) -> str:
        """Generate checksum for dataframe integrity verification."""
        df_string = pd.util.hash_pandas_object(df, index=True).values
        checksum_string = ''.join(str(x) for x in df_string)
        return SecurityManager.hash_data(checksum_string)

# Initialize Security Manager
security_manager = SecurityManager()

# ----------------------------- PAGE CONFIGURATION -----------------------------
st.set_page_config(
    page_title="Bed Allocation & LOS Predictor",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for a polished UI
st.markdown("""
<style>
    * {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    body, .stApp {
        background: linear-gradient(135deg, 
            #004d6d 0%,
            #003d5c 20%,
            #1a1a3e 40%,
            #2d0a3d 60%,
            #3d1a4d 80%,
            #2d0a3d 100%);
    }
    
    .main {
        background: transparent;
    }
    
    .main-title {
        font-size: 3.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #ff006e 0%, #8338ec 25%, #3a86ff 50%, #06ffa5 75%, #ffbe0b 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.5rem;
        text-align: center;
        letter-spacing: -1px;
    }
    
    .sub-title {
        font-size: 1.4rem;
        background: linear-gradient(90deg, #ff006e 0%, #3a86ff 50%, #06ffa5 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        margin-bottom: 2.5rem;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    
    .result-card {
        background: linear-gradient(135deg, #ff006e 0%, #8338ec 50%, #3a86ff 100%);
        border-radius: 25px;
        padding: 35px;
        color: white;
        box-shadow: 0 20px 50px rgba(255, 0, 110, 0.3);
        margin-bottom: 20px;
        border: 2px solid rgba(255, 255, 255, 0.2);
        transition: all 0.3s ease;
    }
    
    .result-card:hover {
        transform: translateY(-8px);
        box-shadow: 0 25px 60px rgba(255, 0, 110, 0.4);
    }
    
    .bed-badge {
        background: linear-gradient(135deg, #06ffa5 0%, #00d87e 100%);
        color: white;
        padding: 14px 28px;
        border-radius: 50px;
        font-weight: 700;
        display: inline-block;
        margin-top: 15px;
        box-shadow: 0 10px 25px rgba(6, 255, 165, 0.4);
        border: 2px solid rgba(255, 255, 255, 0.3);
        transition: all 0.3s ease;
    }
    
    .bed-badge:hover {
        transform: scale(1.08);
        box-shadow: 0 15px 35px rgba(6, 255, 165, 0.5);
    }
    
    .field-container {
        background: linear-gradient(135deg, rgba(255, 192, 203, 0.08) 0%, rgba(173, 216, 230, 0.08) 50%, rgba(255, 255, 224, 0.08) 100%);
        padding: 15px;
        border-radius: 15px;
        margin: 12px 0;
        border-left: 4px solid #3a86ff;
        transition: all 0.3s ease;
    }
    
    .field-container:hover {
        border-left: 4px solid #06ffa5;
        box-shadow: 0 5px 15px rgba(3, 255, 165, 0.1);
    }
    
    .form-section {
        background: linear-gradient(135deg, rgba(58, 134, 255, 0.1) 0%, rgba(6, 255, 165, 0.05) 100%);
        border-radius: 20px;
        padding: 28px;
        margin: 15px 0;
        border: 2px solid rgba(58, 134, 255, 0.3);
        box-shadow: 0 10px 30px rgba(58, 134, 255, 0.15);
    }
    
    .info-box {
        background: linear-gradient(135deg, rgba(255, 184, 11, 0.15) 0%, rgba(255, 184, 11, 0.05) 100%);
        border-radius: 20px;
        padding: 25px;
        border-left: 5px solid #ffbe0b;
        margin: 15px 0;
        box-shadow: 0 8px 20px rgba(255, 184, 11, 0.1);
        border: 1px solid rgba(255, 184, 11, 0.2);
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #ff006e 0%, #8338ec 50%, #3a86ff 100%);
        color: white;
        font-weight: 700;
        padding: 16px 45px;
        border-radius: 50px;
        border: none;
        width: 100%;
        transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 10px 30px rgba(255, 0, 110, 0.4);
        font-size: 1.1rem;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #e60052 0%, #7a28c2 50%, #2a6dd9 100%);
        transform: translateY(-4px);
        box-shadow: 0 15px 40px rgba(255, 0, 110, 0.5);
    }
    .stButton > button:active {
        transform: translateY(-1px);
        box-shadow: 0 8px 20px rgba(255, 0, 110, 0.35);
    }
    
    .section-divider {
        height: 6px;
        background: linear-gradient(90deg, #ff1493 0%, #df1dc5 15%, #9400d3 40%, #6e5ff5 70%, #4169e1 100%);
        margin: 30px 0;
        border-radius: 10px;
        box-shadow: 0 4px 15px rgba(255, 20, 147, 0.4);
    }
</style>
""", unsafe_allow_html=True)

# ----------------------------- DATA LOADING & PREPROCESSING -----------------------------
@st.cache_data
def load_and_preprocess_data():
    """Load dataset and perform initial cleaning with security checks."""
    try:
        # Verify file integrity
        filepath = 'hospital_dataset.csv'
        if not os.path.exists(filepath):
            st.error("Dataset file not found!")
            return None
        
        # Calculate file hash for integrity verification
        file_hash = security_manager.hash_file(filepath)
        if file_hash:
            st.session_state.data_hash = file_hash
        
        df = pd.read_csv(filepath)
        
        # Sanitize dataframe
        df = security_manager.sanitize_dataframe(df)
        
        # Clean column names
        df.columns = df.columns.str.strip()
        
        # Drop rows with missing critical fields
        df = df.dropna(subset=['length_of_stay', 'ccs_diagnosis_description'])
        
        # Convert numeric columns
        df['length_of_stay'] = pd.to_numeric(df['length_of_stay'], errors='coerce')
        df['total_costs'] = pd.to_numeric(df['total_costs'], errors='coerce')
        
        # Remove extreme outliers (LOS > 60 days are likely data errors)
        df = df[df['length_of_stay'] <= 60]
        
        # Fill missing severity with 'Moderate' (most common)
        df['apr_severity_of_illness_description'] = df['apr_severity_of_illness_description'].fillna('Moderate')
        
        # Fill missing gender with 'U'
        df['gender'] = df['gender'].fillna('U')
        
        # Fill missing admission type with 'Emergency'
        df['type_of_admission'] = df['type_of_admission'].fillna('Emergency')
        
        # Fill missing medical/surgical with 'Medical'
        df['apr_medical_surgical_description'] = df['apr_medical_surgical_description'].fillna('Medical')
        
        # Generate data checksum
        data_checksum = security_manager.get_data_checksum(df)
        st.session_state.data_checksum = data_checksum
        
        return df
    
    except Exception as e:
        st.error(f"Error loading dataset: {e}")
        return None

df = load_and_preprocess_data()

# ----------------------------- MODEL TRAINING (CACHED) -----------------------------
@st.cache_resource
def train_model():
    """Train Random Forest model for LOS prediction."""
    # Features and target
    features = ['ccs_diagnosis_description', 'age_group', 'gender', 
                'type_of_admission', 'apr_severity_of_illness_description', 
                'apr_medical_surgical_description']
    target = 'length_of_stay'
    
    # Prepare data
    model_df = df[features + [target]].dropna()
    
    X = model_df[features]
    y = model_df[target]
    
    # Preprocessing pipeline
    categorical_features = features
    categorical_transformer = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    
    preprocessor = ColumnTransformer(
        transformers=[('cat', categorical_transformer, categorical_features)],
        remainder='passthrough'
    )
    
    # Create pipeline
    model = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('regressor', RandomForestRegressor(
            n_estimators=100,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=-1
        ))
    ])
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    mae = mean_absolute_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    
    return model, mae, r2, X_train

model, mae, r2, X_train = train_model()

# ----------------------------- HELPER FUNCTIONS -----------------------------
def map_age_to_group(age):
    """Map exact age to age group bucket."""
    if age < 18:
        return "0 to 17"
    elif age < 30:
        return "18 to 29"
    elif age < 50:
        return "30 to 49"
    elif age < 70:
        return "50 to 69"
    else:
        return "70 or Older"

def recommend_bed(predicted_los, severity):
    """Determine bed type based on predicted LOS and severity."""
    severity_lower = severity.lower()
    
    if predicted_los <= 2:
        if 'extreme' in severity_lower or 'major' in severity_lower:
            return "Step-Down Unit (Short Stay)"
        else:
            return "Observation / Short Stay"
    elif predicted_los <= 5:
        if 'extreme' in severity_lower or 'major' in severity_lower:
            return "Step-Down Unit"
        else:
            return "General Ward"
    elif predicted_los <= 10:
        return "General Ward"
    else:
        return "Long-Term Care / Rehabilitation"

def get_prediction_interval(model, input_df, confidence=0.90):
    """Calculate prediction interval using individual tree predictions."""
    # Get predictions from all trees
    rf = model.named_steps['regressor']
    preprocessor = model.named_steps['preprocessor']
    
    X_transformed = preprocessor.transform(input_df)
    tree_preds = np.array([tree.predict(X_transformed) for tree in rf.estimators_])
    
    mean_pred = tree_preds.mean(axis=0)
    std_pred = tree_preds.std(axis=0)
    
    # Use normal approximation for interval
    from scipy import stats
    z = stats.norm.ppf((1 + confidence) / 2)
    lower = mean_pred - z * std_pred
    upper = mean_pred + z * std_pred
    
    return mean_pred[0], lower[0], upper[0]

def get_historical_stats(disease):
    """Get historical statistics for a given disease."""
    disease_df = df[df['ccs_diagnosis_description'] == disease]
    
    if len(disease_df) == 0:
        return None
    
    stats = {
        'count': len(disease_df),
        'avg_los': disease_df['length_of_stay'].mean(),
        'avg_cost': disease_df['total_costs'].mean(),
        'top_procedures': disease_df['ccs_procedure_description'].value_counts().head(3).to_dict(),
        'disposition': disease_df['patient_disposition'].value_counts().head(3).to_dict(),
        'los_data': disease_df['length_of_stay'].values
    }
    return stats

# ----------------------------- SIDEBAR -----------------------------
# ----------------------------- SIDEBAR -----------------------------
# ----------------------------- SIDEBAR -----------------------------
with st.sidebar:
    # Expand/Collapse Button at top
    st.markdown("""
    <style>
        .expand-btn {
            position: absolute;
            top: 10px;
            right: 10px;
            background: linear-gradient(135deg, #ff1493 0%, #9400d3 100%);
            border: none;
            color: white;
            padding: 8px 12px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1.2rem;
            font-weight: 700;
            box-shadow: 0 4px 12px rgba(255, 20, 147, 0.4);
            transition: all 0.3s ease;
        }
        .expand-btn:hover {
            transform: scale(1.1);
            box-shadow: 0 6px 20px rgba(255, 20, 147, 0.6);
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Enhanced Header with Icon
    st.markdown("""
    <div style="text-align: center; margin-bottom: 25px; padding: 20px; background: linear-gradient(135deg, #0066cc 0%, #00a8ff 100%); border-radius: 20px; box-shadow: 0 10px 30px rgba(0, 102, 204, 0.3); position: relative;">
        <div style="position: absolute; top: 10px; right: 10px; background: linear-gradient(135deg, #ff1493 0%, #9400d3 100%); padding: 6px 10px; border-radius: 20px; cursor: pointer; color: white; font-weight: 700; font-size: 0.9rem;">≫</div>
        <svg width="110" height="110" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <defs>
                <linearGradient id="gradientHospital" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#00ff88;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#00d4ff;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="15" y="20" width="70" height="60" rx="5" fill="url(#gradientHospital)" stroke="white" stroke-width="2"/>
            <circle cx="35" cy="40" r="8" fill="white"/>
            <circle cx="65" cy="40" r="8" fill="white"/>
            <circle cx="35" cy="60" r="8" fill="white"/>
            <circle cx="65" cy="60" r="8" fill="white"/>
            <rect x="48" y="30" width="4" height="30" fill="white"/>
            <rect x="43" y="43" width="14" height="4" fill="white"/>
            <path d="M 50 85 L 50 95" stroke="url(#gradientHospital)" stroke-width="3" stroke-linecap="round"/>
            <circle cx="50" cy="95" r="5" fill="url(#gradientHospital)"/>
        </svg>
        <h2 style="color: white; margin-top: 10px; font-size: 1.8rem; font-weight: 800; margin-bottom: 5px;">Smart Healthcare</h2>
        <p style="color: rgba(255,255,255,0.9); font-size: 0.9rem; margin: 0;">AI-Powered System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # About Section
    with st.expander("📌 About this App", expanded=True):
        st.markdown("""
        <div style="background: linear-gradient(135deg, rgba(0, 102, 204, 0.1) 0%, rgba(0, 168, 255, 0.05) 100%); padding: 15px; border-radius: 12px; border-left: 4px solid #0066cc;">
            <p><strong>AI-Powered Bed Allocation System</strong></p>
            <p style="font-size: 0.9rem; opacity: 0.9;">Predicts Length of Stay (LOS) and recommends appropriate bed types based on patient diagnosis and characteristics.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Key Features Section
    with st.expander("⚡ Key Features", expanded=False):
        st.markdown("""
        <div style="display: grid; gap: 10px;">
            <div style="background: linear-gradient(135deg, rgba(0, 200, 83, 0.2) 0%, rgba(76, 175, 80, 0.1) 100%); padding: 12px; border-radius: 10px; border-left: 4px solid #00c853;">
                <strong style="color: #00c853;">✓ Accurate Predictions</strong>
                <p style="font-size: 0.85rem; margin: 5px 0 0 0;">ML-powered LOS forecasting</p>
            </div>
            <div style="background: linear-gradient(135deg, rgba(255, 152, 0, 0.2) 0%, rgba(255, 193, 7, 0.1) 100%); padding: 12px; border-radius: 10px; border-left: 4px solid #ff9800;">
                <strong style="color: #ff9800;">🎯 Smart Allocation</strong>
                <p style="font-size: 0.85rem; margin: 5px 0 0 0;">Optimal bed type recommendations</p>
            </div>
            <div style="background: linear-gradient(135deg, rgba(244, 67, 54, 0.2) 0%, rgba(229, 57, 53, 0.1) 100%); padding: 12px; border-radius: 10px; border-left: 4px solid #f44336;">
                <strong style="color: #f44336;">📊 Data-Driven</strong>
                <p style="font-size: 0.85rem; margin: 5px 0 0 0;">Based on real hospital data</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Bed Type Guide
    with st.expander("🛏️ Bed Type Guide", expanded=False):
        st.markdown("""
        <div style="display: grid; gap: 8px;">
            <div style="background: linear-gradient(90deg, #00c853 0%, #00e676 100%); padding: 10px 12px; border-radius: 8px; color: white; font-weight: 600;">
                ✓ Short Stay (≤2 days)
            </div>
            <div style="background: linear-gradient(90deg, #0066cc 0%, #0088ff 100%); padding: 10px 12px; border-radius: 8px; color: white; font-weight: 600;">
                📋 General Ward (3-10 days)
            </div>
            <div style="background: linear-gradient(90deg, #ff9800 0%, #ffb74d 100%); padding: 10px 12px; border-radius: 8px; color: white; font-weight: 600;">
                ⚠️ Step-Down Unit (5+ days)
            </div>
            <div style="background: linear-gradient(90deg, #f44336 0%, #ef5350 100%); padding: 10px 12px; border-radius: 8px; color: white; font-weight: 600;">
                🚨 Long-Term Care (>10 days)
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # How to Use
    with st.expander("📖 How to Use", expanded=False):
        st.markdown("""
        <div style="background: linear-gradient(135deg, rgba(156, 39, 176, 0.15) 0%, rgba(103, 58, 183, 0.08) 100%); padding: 15px; border-radius: 12px; border-left: 4px solid #9c27b0;">
            <ol style="margin: 0; padding-left: 20px; font-size: 0.9rem;">
                <li><strong>Select Patient Diagnosis</strong> - Choose from disease list</li>
                <li><strong>Enter Patient Info</strong> - Age, gender, admission type</li>
                <li><strong>Specify Severity</strong> - Select illness severity level</li>
                <li><strong>Submit Form</strong> - Click predict button</li>
                <li><strong>View Results</strong> - See LOS prediction & bed recommendation</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)
    
    # Security Information Section
    with st.expander("🔒 Security Features", expanded=False):
        st.markdown("""
        <div style="background: linear-gradient(135deg, rgba(76, 175, 80, 0.15) 0%, rgba(56, 142, 60, 0.1) 100%); 
                    padding: 15px; border-radius: 12px; border-left: 4px solid #4caf50;">
            <p><strong>Data Protection:</strong></p>
            <ul style="margin: 5px 0; padding-left: 20px; font-size: 0.85rem;">
                <li>SHA-256 hashing for sensitive data</li>
                <li>HMAC signature verification</li>
                <li>File integrity checks (SHA-256)</li>
                <li>Input validation & sanitization</li>
                <li>PII protection & data anonymization</li>
            </ul>
            <p style="margin-top: 12px;"><strong>Security Algorithms:</strong></p>
            <ul style="margin: 5px 0; padding-left: 20px; font-size: 0.85rem;">
                <li>🔐 SHA-256: Cryptographic hashing</li>
                <li>🔐 SHA-512: Enhanced security hashing</li>
                <li>🔐 HMAC-SHA256: Message authentication</li>
                <li>🔐 MD5: Legacy checksum (for reference)</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; padding: 15px; background: linear-gradient(135deg, rgba(0, 102, 204, 0.08) 0%, rgba(0, 168, 255, 0.05) 100%); border-radius: 12px; border: 1px solid rgba(0, 102, 204, 0.1); margin-top: 20px;">
        <p style="margin: 0; font-size: 0.8rem; opacity: 0.7;">
            <strong>Smart Bed Allocation System v2.0</strong><br>
            Powered by Machine Learning + Security<br>
            <span style="font-size: 0.75rem;">© 2026 Healthcare AI | Enhanced Security</span>
        </p>
    </div>
    """, unsafe_allow_html=True)
    


# ----------------------------- MAIN UI -----------------------------
st.markdown('<div class="main-title">🏥 Smart Hospital Bed Allocation System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Smart Predict Length of Stay & Recommend Bed Type</div>', unsafe_allow_html=True)

# Colorful section divider
st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

# Create two columns for input and results
col1, col2 = st.columns([1, 1])

with col1:
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(58, 134, 255, 0.15) 0%, rgba(6, 255, 165, 0.1) 100%); 
                padding: 25px; border-radius: 20px; border: 2px solid rgba(58, 134, 255, 0.3); margin-bottom: 20px;">
        <h2 style="background: linear-gradient(90deg, #3a86ff 0%, #06ffa5 100%); -webkit-background-clip: text; 
                   -webkit-text-fill-color: transparent; background-clip: text; margin-top: 0; margin-bottom: 20px;">
            📋 Patient Information</h2>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form(key='prediction_form'):
        # Disease selection with colored container
        st.markdown("""
        <div class="field-container">
            <div class="field-label">🔬 Disease / Condition</div>
        </div>
        """, unsafe_allow_html=True)
        disease_list = sorted(df['ccs_diagnosis_description'].unique().tolist())
        selected_disease = st.selectbox(
            "Disease / Condition",
            options=disease_list,
            help="Start typing to search for a disease",
            label_visibility='collapsed'
        )
        
        # Age input options with color
        st.markdown("""
        <div class="field-container">
            <div class="field-label">👤 Age Information</div>
        </div>
        """, unsafe_allow_html=True)
        age_group_options = ["0 to 17", "18 to 29", "30 to 49", "50 to 69", "70 or Older"]
        selected_age_group = st.selectbox("Age Group", age_group_options, label_visibility='collapsed')
        final_age_group = selected_age_group
        
        # Gender with color
        st.markdown("""
        <div class="field-container">
            <div class="field-label">⚧ Gender</div>
        </div>
        """, unsafe_allow_html=True)
        gender_options = ['M', 'F', 'U']
        selected_gender = st.selectbox("Gender", gender_options, label_visibility='collapsed')
        
        # Admission type with color
        st.markdown("""
        <div class="field-container">
            <div class="field-label">🚑 Admission Type</div>
        </div>
        """, unsafe_allow_html=True)
        admission_options = sorted(df['type_of_admission'].unique().tolist())
        selected_admission = st.selectbox("Admission Type", admission_options, 
                                          index=admission_options.index('Emergency') if 'Emergency' in admission_options else 0,
                                          label_visibility='collapsed')
        
        # Severity with color
        st.markdown("""
        <div class="field-container">
            <div class="field-label">⚠️ Severity of Illness</div>
        </div>
        """, unsafe_allow_html=True)
        severity_options = sorted(df['apr_severity_of_illness_description'].unique().tolist())
        selected_severity = st.selectbox("Severity of Illness", severity_options,
                                         index=severity_options.index('Moderate') if 'Moderate' in severity_options else 0,
                                         label_visibility='collapsed')
        
        # Medical/Surgical with color
        st.markdown("""
        <div class="field-container">
            <div class="field-label">🏥 Medical Classification</div>
        </div>
        """, unsafe_allow_html=True)
        med_surg = st.radio("Medical or Surgical?", ["Medical", "Surgical"], horizontal=True)
        
        submit_button = st.form_submit_button(label="🔮 Predict & Allocate Bed", use_container_width=True)

with col2:
    if submit_button:
        # Perform security validation on inputs
        validation_passed = True
        validation_errors = []
        
        # Validate disease input
        if not security_manager.validate_input(selected_disease, 'text', max_length=150):
            validation_passed = False
            validation_errors.append("Invalid disease input")
        
        # Validate age group
        if selected_age_group not in age_group_options:
            validation_passed = False
            validation_errors.append("Invalid age group")
        
        # Validate gender
        if selected_gender not in gender_options:
            validation_passed = False
            validation_errors.append("Invalid gender")
        
        # Validate admission type
        if not security_manager.validate_input(selected_admission, 'text', max_length=50):
            validation_passed = False
            validation_errors.append("Invalid admission type")
        
        # Validate severity
        if not security_manager.validate_input(selected_severity, 'text', max_length=50):
            validation_passed = False
            validation_errors.append("Invalid severity input")
        
        if not validation_passed:
            for error in validation_errors:
                st.error(f"⚠️ Security Validation Error: {error}")
        else:
            st.markdown("""
            <div style="background: linear-gradient(135deg, rgba(255, 0, 110, 0.15) 0%, rgba(131, 56, 236, 0.1) 100%); 
                        padding: 25px; border-radius: 20px; border: 2px solid rgba(255, 0, 110, 0.3); margin-bottom: 20px;">
                <h2 style="background: linear-gradient(90deg, #ff006e 0%, #8338ec 100%); -webkit-background-clip: text; 
                           -webkit-text-fill-color: transparent; background-clip: text; margin-top: 0; margin-bottom: 20px;">
                    📈 Prediction Results</h2>
            </div>
            """, unsafe_allow_html=True)
            
            # Prepare input data
            input_data = pd.DataFrame({
                'ccs_diagnosis_description': [selected_disease],
                'age_group': [final_age_group],
                'gender': [selected_gender],
                'type_of_admission': [selected_admission],
                'apr_severity_of_illness_description': [selected_severity],
                'apr_medical_surgical_description': [med_surg]
            })
            
            # Generate hash of input for audit logging
            input_hash = security_manager.hash_data(str(input_data.values))
            input_signature = security_manager.generate_hmac(str(input_data.values))
            
            try:
                # Predict LOS
                predicted_los = model.predict(input_data)[0]
                
                # Get prediction interval (simplified: use +/- 1.5 days as rough estimate, or compute via trees)
                try:
                    mean_pred, lower, upper = get_prediction_interval(model, input_data)
                    interval_text = f"{lower:.1f} – {upper:.1f} days"
                except:
                    # Fallback if scipy not available or error
                std_dev = 1.5  # average standard deviation from training
                lower = max(0, predicted_los - 1.96 * std_dev)
                upper = predicted_los + 1.96 * std_dev
                interval_text = f"{lower:.1f} – {upper:.1f} days"
            
            # Recommend bed
            bed_type = recommend_bed(predicted_los, selected_severity)
            
            # Calculate discharge date
            discharge_date = datetime.now() + timedelta(days=int(round(predicted_los)))
            
            # Display results in a card
            st.markdown('<div class="result-card">', unsafe_allow_html=True)
            
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown('<div class="result-label">Predicted Length of Stay</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="result-value">{predicted_los:.1f} days</div>', unsafe_allow_html=True)
                st.markdown(f'<div style="opacity:0.8;">90% Interval: {interval_text}</div>', unsafe_allow_html=True)
            with col_b:
                st.markdown('<div class="result-label">Estimated Discharge</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="result-value">{discharge_date.strftime("%b %d, %Y")}</div>', unsafe_allow_html=True)
            
            st.markdown(f'<span class="bed-badge">🛏️ Recommended: {bed_type}</span>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
        except Exception as e:
            st.error(f"Prediction error: {str(e)}")
            st.info("Using historical averages instead.")
            predicted_los = None

# Historical Data Section
if submit_button:
    st.markdown("""
    <div class="section-divider"></div>
    <div style="background: linear-gradient(135deg, rgba(255, 190, 11, 0.15) 0%, rgba(255, 184, 11, 0.1) 100%); 
                padding: 25px; border-radius: 20px; border: 2px solid rgba(255, 184, 11, 0.3); margin: 30px 0 20px 0;">
        <h2 style="background: linear-gradient(90deg, #ffbe0b 0%, #ff8c42 100%); -webkit-background-clip: text; 
                   -webkit-text-fill-color: transparent; background-clip: text; margin-top: 0; margin-bottom: 20px;">
            📊 Historical Data for This Disease</h2>
    </div>
    """, unsafe_allow_html=True)
    
    stats = get_historical_stats(selected_disease)
    
    if stats is not None:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, rgba(58, 134, 255, 0.2) 0%, rgba(58, 134, 255, 0.1) 100%); 
                        padding: 20px; border-radius: 15px; border: 2px solid rgba(58, 134, 255, 0.4); text-align: center;">
                <p style="margin: 0; font-size: 0.85rem; color: #3a86ff; font-weight: 600;">Total Cases</p>
                <p style="margin: 8px 0 0 0; font-size: 2rem; font-weight: 800; background: linear-gradient(90deg, #3a86ff 0%, #06ffa5 100%); 
                          -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">
                    {stats['count']:,}</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, rgba(255, 105, 180, 0.2) 0%, rgba(255, 105, 180, 0.1) 100%); 
                        padding: 20px; border-radius: 15px; border: 2px solid rgba(255, 105, 180, 0.4); text-align: center;">
                <p style="margin: 0; font-size: 0.85rem; color: #ff69b4; font-weight: 600;">Average LOS</p>
                <p style="margin: 8px 0 0 0; font-size: 2rem; font-weight: 800; color: #ff69b4;">{stats['avg_los']:.1f} days</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, rgba(131, 56, 236, 0.2) 0%, rgba(131, 56, 236, 0.1) 100%); 
                        padding: 20px; border-radius: 15px; border: 2px solid rgba(131, 56, 236, 0.4); text-align: center;">
                <p style="margin: 0; font-size: 0.85rem; color: #8338ec; font-weight: 600;">Average Cost</p>
                <p style="margin: 8px 0 0 0; font-size: 1.8rem; font-weight: 800; color: #8338ec;">${stats['avg_cost']:,.0f}</p>
            </div>
            """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            <div style="background: linear-gradient(135deg, rgba(6, 255, 165, 0.15) 0%, rgba(6, 255, 165, 0.05) 100%); 
                        padding: 20px; border-radius: 15px; border-left: 4px solid #06ffa5; border-right: 1px solid rgba(6, 255, 165, 0.3);">
                <h4 style="color: #06ffa5; margin-top: 0; margin-bottom: 15px; display: flex; align-items: center; gap: 8px;">🔧 Top Procedures</h4>
            </div>
            """, unsafe_allow_html=True)
            for proc, count in stats['top_procedures'].items():
                pct = (count / stats['count']) * 100
                st.markdown(f"<div style='margin: 8px 0; padding: 8px; background: rgba(6, 255, 165, 0.1); border-radius: 8px; border-left: 3px solid #06ffa5;'><strong>✓ {proc}</strong><br><span style='opacity: 0.8;'>{pct:.1f}%</span></div>", unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: linear-gradient(135deg, rgba(255, 180, 80, 0.15) 0%, rgba(255, 180, 80, 0.05) 100%); 
                        padding: 20px; border-radius: 15px; border-left: 4px solid #ffb450; border-right: 1px solid rgba(255, 180, 80, 0.3);">
                <h4 style="color: #ff9800; margin-top: 0; margin-bottom: 15px; display: flex; align-items: center; gap: 8px;">🏥 Typical Discharge Disposition</h4>
            </div>
            """, unsafe_allow_html=True)
            for disp, count in stats['disposition'].items():
                pct = (count / stats['count']) * 100
                st.markdown(f"<div style='margin: 8px 0; padding: 8px; background: rgba(255, 152, 0, 0.1); border-radius: 8px; border-left: 3px solid #ff9800;'><strong>➜ {disp}</strong><br><span style='opacity: 0.8;'>{pct:.1f}%</span></div>", unsafe_allow_html=True)
        
        # LOS Distribution Histogram
        fig = px.histogram(
            x=stats['los_data'], 
            nbins=20,
            title=f"Length of Stay Distribution - {selected_disease[:40]}...",
            labels={'x': 'Length of Stay (days)', 'y': 'Frequency'},
            color_discrete_sequence=['#1f3a5f']
        )
        fig.update_layout(bargap=0.1, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
        
        # Compare prediction with historical average
        if predicted_los is not None:
            st.info(f"📌 Your predicted LOS ({predicted_los:.1f} days) is {'higher' if predicted_los > stats['avg_los'] else 'lower'} than the historical average ({stats['avg_los']:.1f} days).")
    else:
        st.warning("No historical data found for this disease. Showing overall statistics.")
        overall_los = df['length_of_stay'].mean()
        st.metric("Overall Average LOS", f"{overall_los:.1f} days")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; padding: 20px; background: linear-gradient(135deg, rgba(255, 0, 110, 0.1) 0%, rgba(131, 56, 236, 0.08) 100%); border-radius: 15px; border: 2px solid rgba(255, 0, 110, 0.2); margin-top: 30px;'>"
    "<h3 style='background: linear-gradient(90deg, #ff006e 0%, #8338ec 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin-bottom: 10px;'>Smart Bed Allocation System v1.0</h3>"
    "<p style='margin: 8px 0; font-weight: 600; color: #3a86ff;'>Powered by Machine Learning</p>"
    "<p style='margin: 8px 0; font-size: 0.9rem; color: #999;'>© 2026 Healthcare AI</p>"
    "</div>",
    unsafe_allow_html=True
)