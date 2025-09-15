from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import hashlib
import secrets
import json
from enum import Enum
import jwt
from passlib.context import CryptContext
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import asyncio
import random

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
SECRET_KEY = "ashcodex_zkp_iot_secret_key_2024"
ALGORITHM = "HS256"

# Create the main app
app = FastAPI(title="AshCodex ZKP IoT Authentication System", version="2.0.0")
api_router = APIRouter(prefix="/api")

# Enums
class DeviceType(str, Enum):
    SMART_HOME = "smart_home"
    HEALTHCARE = "healthcare"
    INDUSTRIAL = "industrial"
    WEARABLE = "wearable"
    SENSOR = "sensor"

class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    AUTHENTICATING = "authenticating"
    COMPROMISED = "compromised"
    MAINTENANCE = "maintenance"

class AuthMethod(str, Enum):
    TRADITIONAL = "traditional"
    ZERO_KNOWLEDGE = "zero_knowledge"
    MULTI_FACTOR_ZKP = "multi_factor_zkp"

class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVICE_MANAGER = "device_manager"

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Data Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    hashed_password: str
    role: UserRole
    zkp_secret: str = ""
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.DEVICE_MANAGER

class UserLogin(BaseModel):
    username: str
    password: str
    zkp_proof: Optional[str] = None

class IoTDevice(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_name: str
    device_type: DeviceType
    manufacturer: str
    mac_address: str
    location: str
    status: DeviceStatus = DeviceStatus.OFFLINE
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    zkp_identity_hash: str = ""
    risk_score: float = 0.0
    anomaly_score: float = 0.0
    maintenance_prediction: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class IoTDeviceCreate(BaseModel):
    device_name: str
    device_type: DeviceType
    manufacturer: str
    mac_address: str
    location: str

class ZKProof(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    proof_hash: str
    challenge: str
    response: str
    verifier_result: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
class AuthenticationLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    device_name: str
    auth_method: AuthMethod
    success: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: str = "127.0.0.1"
    risk_score: float = 0.0
    privacy_preserved: bool = True

class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    device_id: str
    severity: str
    description: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    ml_predicted: bool = False

class ThreatPrediction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    threat_type: str
    probability: float
    severity: ThreatLevel
    predicted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str
    recommended_action: str

class MLInsight(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    insight_type: str  # anomaly, threat, maintenance, risk
    device_id: Optional[str] = None
    confidence: float
    description: str
    recommendations: List[str]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class DashboardStats(BaseModel):
    total_devices: int
    online_devices: int
    successful_auths_today: int
    failed_auths_today: int
    avg_privacy_score: float
    threat_level: str
    ml_predictions_today: int
    anomalies_detected: int
    maintenance_alerts: int

# ML Models and Helper Functions
class MLPredictor:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.threat_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.risk_scaler = StandardScaler()
        self.is_trained = False
        
    async def train_models(self):
        """Train ML models with historical data"""
        # Generate synthetic training data for demo
        np.random.seed(42)
        
        # Normal device behavior patterns
        normal_data = np.random.normal(0, 1, (1000, 8))
        
        # Anomalous behavior patterns  
        anomaly_data = np.random.normal(3, 2, (100, 8))
        
        # Train anomaly detector
        training_data = np.vstack([normal_data, anomaly_data])
        self.anomaly_detector.fit(training_data)
        
        # Train threat classifier
        threat_features = np.random.random((500, 6))
        threat_labels = np.random.choice([0, 1], 500, p=[0.7, 0.3])
        self.threat_classifier.fit(threat_features, threat_labels)
        
        self.is_trained = True
        
    def predict_anomaly(self, device_metrics: Dict) -> float:
        """Predict if device behavior is anomalous"""
        if not self.is_trained:
            return random.uniform(0.1, 0.3)
            
        features = np.array([[
            device_metrics.get('cpu_usage', 0.5),
            device_metrics.get('memory_usage', 0.4),
            device_metrics.get('network_traffic', 0.3),
            device_metrics.get('auth_frequency', 0.2),
            device_metrics.get('response_time', 0.1),
            device_metrics.get('error_rate', 0.05),
            device_metrics.get('data_volume', 0.6),
            device_metrics.get('connection_duration', 0.7)
        ]])
        
        anomaly_score = self.anomaly_detector.decision_function(features)[0]
        # Convert to 0-1 scale where higher is more anomalous
        return max(0, min(1, (anomaly_score + 0.5) * -1))
    
    def predict_threat(self, device_data: Dict) -> Dict:
        """Predict potential security threats"""
        threat_types = [
            "DDoS Attack", "Malware Infection", "Unauthorized Access",
            "Data Exfiltration", "Firmware Tampering", "Network Intrusion"
        ]
        
        # Simulate ML prediction
        threat_probability = random.uniform(0.1, 0.9)
        threat_type = random.choice(threat_types)
        
        severity = ThreatLevel.LOW
        if threat_probability > 0.7:
            severity = ThreatLevel.CRITICAL
        elif threat_probability > 0.5:
            severity = ThreatLevel.HIGH
        elif threat_probability > 0.3:
            severity = ThreatLevel.MEDIUM
            
        return {
            "threat_type": threat_type,
            "probability": threat_probability,
            "severity": severity,
            "description": f"ML model detected potential {threat_type.lower()} with {threat_probability:.1%} confidence"
        }
    
    def predict_maintenance(self, device_data: Dict) -> float:
        """Predict device maintenance needs"""
        # Factors affecting maintenance prediction
        age_factor = min(1.0, device_data.get('days_since_created', 0) / 365)
        usage_factor = device_data.get('usage_intensity', 0.5)
        error_factor = device_data.get('error_rate', 0.1)
        
        maintenance_score = (age_factor * 0.4 + usage_factor * 0.4 + error_factor * 0.2)
        return min(1.0, maintenance_score + random.uniform(-0.1, 0.1))
    
    def calculate_risk_score(self, device_data: Dict, auth_history: List) -> float:
        """Calculate comprehensive risk score"""
        base_risk = 0.2
        
        # Authentication failure rate
        if auth_history:
            failed_auths = sum(1 for auth in auth_history if not auth.get('success', True))
            failure_rate = failed_auths / len(auth_history)
            auth_risk = failure_rate * 0.3
        else:
            auth_risk = 0.1
            
        # Device status risk
        status_risk = {
            'online': 0.1,
            'offline': 0.3,
            'compromised': 0.9,
            'maintenance': 0.4
        }.get(device_data.get('status', 'offline'), 0.5)
        
        # Location and type risk
        location_risk = 0.1 if 'secure' in device_data.get('location', '').lower() else 0.2
        type_risk = {
            'healthcare': 0.3,
            'industrial': 0.4,
            'smart_home': 0.1,
            'wearable': 0.2,
            'sensor': 0.15
        }.get(device_data.get('device_type', 'sensor'), 0.2)
        
        total_risk = min(1.0, base_risk + auth_risk + status_risk * 0.3 + location_risk + type_risk)
        return round(total_risk, 3)

# Initialize ML predictor
ml_predictor = MLPredictor()

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

def require_role(required_roles: List[UserRole]):
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in [role.value for role in required_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    return role_checker

# Helper Functions
def generate_zkp_identity_hash(device_name: str, mac_address: str) -> str:
    combined = f"{device_name}:{mac_address}:{secrets.token_hex(16)}"
    return hashlib.sha256(combined.encode()).hexdigest()

def simulate_zkp_proof(device_id: str, identity_hash: str) -> ZKProof:
    challenge = secrets.token_hex(32)
    proof_data = f"{identity_hash}:{challenge}:{secrets.token_hex(16)}"
    proof_hash = hashlib.sha256(proof_data.encode()).hexdigest()
    response = hashlib.sha256(f"{proof_hash}:{challenge}".encode()).hexdigest()
    
    verifier_result = True
    
    return ZKProof(
        device_id=device_id,
        proof_hash=proof_hash,
        challenge=challenge,
        response=response,
        verifier_result=verifier_result
    )

# Initialize default admin user
async def create_default_users():
    try:
        # Check if admin exists
        admin_exists = await db.users.find_one({"username": "admin"})
        if not admin_exists:
            admin_user = User(
                username="admin",
                email="admin@ashcodex.com",
                hashed_password=get_password_hash("admin123"),
                role=UserRole.ADMIN,
                zkp_secret=secrets.token_hex(32)
            )
            admin_dict = admin_user.dict()
            admin_dict['created_at'] = admin_dict['created_at'].isoformat()
            await db.users.insert_one(admin_dict)
            
        # Create security analyst
        analyst_exists = await db.users.find_one({"username": "analyst"})
        if not analyst_exists:
            analyst_user = User(
                username="analyst",
                email="analyst@ashcodex.com", 
                hashed_password=get_password_hash("analyst123"),
                role=UserRole.SECURITY_ANALYST,
                zkp_secret=secrets.token_hex(32)
            )
            analyst_dict = analyst_user.dict()
            analyst_dict['created_at'] = analyst_dict['created_at'].isoformat()
            await db.users.insert_one(analyst_dict)
            
        # Create device manager
        manager_exists = await db.users.find_one({"username": "manager"})
        if not manager_exists:
            manager_user = User(
                username="manager",
                email="manager@ashcodex.com",
                hashed_password=get_password_hash("manager123"),
                role=UserRole.DEVICE_MANAGER,
                zkp_secret=secrets.token_hex(32)
            )
            manager_dict = manager_user.dict()
            manager_dict['created_at'] = manager_dict['created_at'].isoformat()
            await db.users.insert_one(manager_dict)
            
    except Exception as e:
        logging.error(f"Error creating default users: {e}")

# API Routes
@api_router.post("/auth/login")
async def login(user_login: UserLogin):
    user = await db.users.find_one({"username": user_login.username})
    if not user or not verify_password(user_login.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # For multi-factor ZKP authentication
    if user_login.zkp_proof:
        # Verify ZKP proof (simplified for demo)
        expected_proof = hashlib.sha256(f"{user['zkp_secret']}:{user_login.username}".encode()).hexdigest()
        if user_login.zkp_proof != expected_proof:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid ZKP proof"
            )
    
    # Update last login
    await db.users.update_one(
        {"username": user_login.username},
        {"$set": {"last_login": datetime.now(timezone.utc).isoformat()}}
    )
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
    }

@api_router.post("/auth/register")
async def register(user_create: UserCreate, current_user: dict = Depends(require_role([UserRole.ADMIN]))):
    # Check if user exists
    existing_user = await db.users.find_one({"username": user_create.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    user = User(
        username=user_create.username,
        email=user_create.email,
        hashed_password=get_password_hash(user_create.password),
        role=user_create.role,
        zkp_secret=secrets.token_hex(32)
    )
    
    user_dict = user.dict()
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    await db.users.insert_one(user_dict)
    
    return {"message": "User registered successfully", "zkp_secret": user.zkp_secret}

@api_router.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "role": current_user["role"],
        "zkp_secret": current_user.get("zkp_secret", "")
    }

@api_router.post("/devices", response_model=IoTDevice)
async def register_device(device_data: IoTDeviceCreate, current_user: dict = Depends(require_role([UserRole.ADMIN, UserRole.DEVICE_MANAGER]))):
    zkp_hash = generate_zkp_identity_hash(device_data.device_name, device_data.mac_address)
    
    device = IoTDevice(
        **device_data.dict(),
        zkp_identity_hash=zkp_hash,
        status=DeviceStatus.ONLINE
    )
    
    # Calculate initial ML scores
    device_metrics = {
        'cpu_usage': random.uniform(0.1, 0.8),
        'memory_usage': random.uniform(0.2, 0.7),
        'network_traffic': random.uniform(0.1, 0.9),
        'auth_frequency': random.uniform(0.1, 0.5),
        'response_time': random.uniform(0.05, 0.3),
        'error_rate': random.uniform(0.01, 0.1),
        'data_volume': random.uniform(0.2, 0.8),
        'connection_duration': random.uniform(0.3, 0.9)
    }
    
    device.anomaly_score = ml_predictor.predict_anomaly(device_metrics)
    device.risk_score = ml_predictor.calculate_risk_score(device.dict(), [])
    device.maintenance_prediction = ml_predictor.predict_maintenance({
        'days_since_created': 0,
        'usage_intensity': random.uniform(0.2, 0.8),
        'error_rate': device_metrics['error_rate']
    })
    
    device_dict = device.dict()
    device_dict['last_seen'] = device_dict['last_seen'].isoformat()
    device_dict['created_at'] = device_dict['created_at'].isoformat()
    
    await db.devices.insert_one(device_dict)
    
    # Log registration event
    event = SecurityEvent(
        event_type="device_registration",
        device_id=device.id,
        severity="low",
        description=f"New device {device.device_name} registered with ZKP authentication"
    )
    event_dict = event.dict()
    event_dict['timestamp'] = event_dict['timestamp'].isoformat()
    await db.security_events.insert_one(event_dict)
    
    return device

@api_router.get("/devices", response_model=List[IoTDevice])
async def get_devices(current_user: dict = Depends(get_current_user)):
    devices = await db.devices.find().to_list(1000)
    result = []
    for device in devices:
        device['last_seen'] = datetime.fromisoformat(device['last_seen'])
        device['created_at'] = datetime.fromisoformat(device['created_at'])
        result.append(IoTDevice(**device))
    return result

@api_router.post("/authenticate/{device_id}")
async def authenticate_device(device_id: str, auth_method: AuthMethod = AuthMethod.ZERO_KNOWLEDGE, current_user: dict = Depends(get_current_user)):
    device_data = await db.devices.find_one({"id": device_id})
    if not device_data:
        raise HTTPException(status_code=404, detail="Device not found")
    
    success = True
    privacy_preserved = auth_method in [AuthMethod.ZERO_KNOWLEDGE, AuthMethod.MULTI_FACTOR_ZKP]
    
    if auth_method in [AuthMethod.ZERO_KNOWLEDGE, AuthMethod.MULTI_FACTOR_ZKP]:
        zkp_proof = simulate_zkp_proof(device_id, device_data['zkp_identity_hash'])
        
        proof_dict = zkp_proof.dict()
        proof_dict['timestamp'] = proof_dict['timestamp'].isoformat()
        await db.zkp_proofs.insert_one(proof_dict)
        
        success = zkp_proof.verifier_result
    
    # Get recent auth history for risk calculation
    recent_auths = await db.auth_logs.find({"device_id": device_id}).sort("timestamp", -1).limit(10).to_list(10)
    risk_score = ml_predictor.calculate_risk_score(device_data, recent_auths)
    
    auth_log = AuthenticationLog(
        device_id=device_id,
        device_name=device_data['device_name'],
        auth_method=auth_method,
        success=success,
        risk_score=risk_score,
        privacy_preserved=privacy_preserved
    )
    
    log_dict = auth_log.dict()
    log_dict['timestamp'] = log_dict['timestamp'].isoformat()
    await db.auth_logs.insert_one(log_dict)
    
    # Update device status and run ML predictions
    await db.devices.update_one(
        {"id": device_id},
        {"$set": {"status": "online", "last_seen": datetime.now(timezone.utc).isoformat(), "risk_score": risk_score}}
    )
    
    # Generate threat prediction
    threat_prediction = ml_predictor.predict_threat(device_data)
    if threat_prediction["probability"] > 0.6:
        threat = ThreatPrediction(
            device_id=device_id,
            threat_type=threat_prediction["threat_type"],
            probability=threat_prediction["probability"],
            severity=threat_prediction["severity"],
            description=threat_prediction["description"],
            recommended_action=f"Investigate {threat_prediction['threat_type'].lower()} indicators and enhance monitoring"
        )
        threat_dict = threat.dict()
        threat_dict['predicted_at'] = threat_dict['predicted_at'].isoformat()
        await db.threat_predictions.insert_one(threat_dict)
    
    return {
        "success": success,
        "auth_method": auth_method,
        "privacy_preserved": privacy_preserved,
        "risk_score": risk_score,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@api_router.get("/ml/predictions", response_model=List[ThreatPrediction])
async def get_threat_predictions(current_user: dict = Depends(require_role([UserRole.ADMIN, UserRole.SECURITY_ANALYST]))):
    predictions = await db.threat_predictions.find().sort("predicted_at", -1).limit(50).to_list(50)
    result = []
    for pred in predictions:
        pred['predicted_at'] = datetime.fromisoformat(pred['predicted_at'])
        result.append(ThreatPrediction(**pred))
    return result

@api_router.get("/ml/insights")
async def get_ml_insights(current_user: dict = Depends(get_current_user)):
    """Get comprehensive ML insights"""
    devices = await db.devices.find().to_list(1000)
    insights = []
    
    # Anomaly detection insights
    high_anomaly_devices = [d for d in devices if d.get('anomaly_score', 0) > 0.7]
    if high_anomaly_devices:
        insights.append(MLInsight(
            insight_type="anomaly",
            confidence=0.85,
            description=f"Detected {len(high_anomaly_devices)} devices with suspicious behavior patterns",
            recommendations=["Investigate flagged devices", "Review authentication logs", "Consider device isolation"]
        ))
    
    # Risk assessment insights  
    high_risk_devices = [d for d in devices if d.get('risk_score', 0) > 0.6]
    if high_risk_devices:
        insights.append(MLInsight(
            insight_type="risk",
            confidence=0.78,
            description=f"{len(high_risk_devices)} devices classified as high-risk based on behavioral analysis",
            recommendations=["Implement additional authentication factors", "Increase monitoring frequency", "Update security policies"]
        ))
    
    # Maintenance predictions
    maintenance_needed = [d for d in devices if d.get('maintenance_prediction', 0) > 0.8]
    if maintenance_needed:
        insights.append(MLInsight(
            insight_type="maintenance",
            confidence=0.72,
            description=f"{len(maintenance_needed)} devices predicted to require maintenance soon",
            recommendations=["Schedule preventive maintenance", "Update device firmware", "Replace aging components"]
        ))
    
    # Convert to dict format
    result = []
    for insight in insights:
        insight_dict = insight.dict()
        insight_dict['timestamp'] = insight_dict['timestamp'].isoformat()
        result.append(insight_dict)
    
    return result

@api_router.get("/authentication-logs", response_model=List[AuthenticationLog])
async def get_authentication_logs(current_user: dict = Depends(get_current_user)):
    logs = await db.auth_logs.find().sort("timestamp", -1).limit(100).to_list(100)
    result = []
    for log in logs:
        log['timestamp'] = datetime.fromisoformat(log['timestamp'])
        result.append(AuthenticationLog(**log))
    return result

@api_router.get("/security-events", response_model=List[SecurityEvent])
async def get_security_events(current_user: dict = Depends(get_current_user)):
    events = await db.security_events.find().sort("timestamp", -1).limit(50).to_list(50)
    result = []
    for event in events:
        event['timestamp'] = datetime.fromisoformat(event['timestamp'])
        result.append(SecurityEvent(**event))
    return result

@api_router.get("/dashboard-stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    total_devices = await db.devices.count_documents({})
    online_devices = await db.devices.count_documents({"status": "online"})
    
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    successful_auths = await db.auth_logs.count_documents({
        "timestamp": {"$gte": today.isoformat()},
        "success": True
    })
    failed_auths = await db.auth_logs.count_documents({
        "timestamp": {"$gte": today.isoformat()},
        "success": False
    })
    
    privacy_logs = await db.auth_logs.find({"privacy_preserved": True}).to_list(1000)
    avg_privacy = len(privacy_logs) / max(total_devices, 1) * 100 if total_devices > 0 else 0
    
    # ML-specific stats
    ml_predictions_today = await db.threat_predictions.count_documents({
        "predicted_at": {"$gte": today.isoformat()}
    })
    
    devices_list = await db.devices.find().to_list(1000)
    anomalies_detected = len([d for d in devices_list if d.get('anomaly_score', 0) > 0.6])
    maintenance_alerts = len([d for d in devices_list if d.get('maintenance_prediction', 0) > 0.7])
    
    recent_events = await db.security_events.find({
        "timestamp": {"$gte": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()}
    }).to_list(100)
    
    threat_level = "low"
    if len(recent_events) > 10:
        threat_level = "medium"
    if len(recent_events) > 25:
        threat_level = "high"
    if anomalies_detected > 5:
        threat_level = "critical"
    
    return DashboardStats(
        total_devices=total_devices,
        online_devices=online_devices,
        successful_auths_today=successful_auths,
        failed_auths_today=failed_auths,
        avg_privacy_score=round(avg_privacy, 1),
        threat_level=threat_level,
        ml_predictions_today=ml_predictions_today,
        anomalies_detected=anomalies_detected,
        maintenance_alerts=maintenance_alerts
    )

@api_router.get("/simulate-threat")
async def simulate_threat(current_user: dict = Depends(require_role([UserRole.ADMIN, UserRole.SECURITY_ANALYST]))):
    devices = await db.devices.find().to_list(10)
    if not devices:
        raise HTTPException(status_code=400, detail="No devices to simulate threat on")
    
    device = random.choice(devices)
    
    threat_types = [
        "unauthorized_access_attempt",
        "suspicious_authentication_pattern", 
        "potential_device_compromise",
        "anomalous_network_behavior",
        "ml_predicted_malware",
        "zkp_protocol_violation"
    ]
    
    event = SecurityEvent(
        event_type=random.choice(threat_types),
        device_id=device['id'],
        severity=random.choice(["medium", "high", "critical"]),
        description=f"ML-enhanced threat simulation detected on {device['device_name']}",
        ml_predicted=True
    )
    
    event_dict = event.dict()
    event_dict['timestamp'] = event_dict['timestamp'].isoformat()
    await db.security_events.insert_one(event_dict)
    
    return {"message": "Advanced threat simulation created", "event": event}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_db():
    await create_default_users()
    await ml_predictor.train_models()
    logger.info("AshCodex ZKP IoT Authentication System started successfully")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()