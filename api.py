from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import validates
from sqlalchemy import case

from dbserver import (
    Base,
    User,
    Organization,
    AutoTQ,
    DeviceStatusRecord,
    DeviceGroup,
    DeviceStatusEnum,
    Firmware,
    create_test_data,
    FirmwareDeploymentStageEnum,
)

import os
import uuid
import json
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from sqlalchemy.orm import validates
import re
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator

# improt Request
from fastapi import Request

# import Response
from fastapi import Response

# Path to your existing database
DATABASE_URL = "sqlite:///autotq.db"  # Make sure this points to the correct path

# Create the engine and sessionmaker
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.bind = engine

# Authentication Setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI App
app = FastAPI()

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authentication Functions
async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    user = db.query(User).filter(User.user_id == token).first()
    if not user:
        print(f"Token received: {token}")  # Debugging step
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

async def authenticate_user(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticates a user based on username and password."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not pwd_context.verify(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Generate a token (in a real app, you'd use JWT)
    token = user.user_id
    return {"access_token": token, "token_type": "bearer"}

class UserCreate(BaseModel):
    username: str = Field(..., max_length=50)
    email: str
    phone_number: str
    password: str
    first_name: str
    last_name: str
    address: str

    @validator('email')
    def validate_email(cls, value):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            raise ValueError('Invalid email address')
        return value

    @validator('phone_number')
    def validate_phone(cls, value):
        # Remove any non-digit characters for validation
        clean_phone = re.sub(r'\D', '', value)
        if not 10 <= len(clean_phone) <= 15:  # Accept international numbers
            raise ValueError('Invalid phone number length')
        return value

    @validator('username')
    def validate_username(cls, value):
        if not re.match(r'^[a-zA-Z0-9_]{3,50}$', value):
            raise ValueError('Username must be 3-50 characters long and contain only letters, numbers, and underscores')
        return value

class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    phone_number: str
    first_name: str
    last_name: str
    address: str
    organization_id: Optional[str] = None
    created_at: datetime
    last_modified: datetime

    class Config:
        orm_mode = True

class OrganizationCreate(BaseModel):
    name: str
    address: str

class OrganizationResponse(BaseModel):
    org_id: str
    name: str
    address: str
    owner_id: str
    created_at: datetime
    last_modified: datetime

    class Config:
        orm_mode = True

class AutoTQCreate(BaseModel):
    mac_address: str
    serial_number: str
    human_readable_name: str
    auto_update_enabled: Optional[bool] = False
    device_group_id: Optional[str] = None

class AutoTQResponse(BaseModel):
    device_id: str
    mac_address: str
    serial_number: str
    human_readable_name: str
    firmware_id: Optional[str] = None  # Reference to the Firmware object
    auto_update_enabled: Optional[bool] = False
    owner_id: str
    organization_id: str
    device_group_id: Optional[str] = None
    latest_status_id: Optional[str] = None
    created_at: datetime
    last_modified: datetime
    training_completed_at: Optional[datetime] = None
    order_placed_at: Optional[datetime] = None
    arrival_date: Optional[datetime] = None
    last_active_at: Optional[datetime] = None
    last_firmware_update: Optional[datetime] = None

    class Config:
        orm_mode = True

class DeviceStatusRecordResponse(BaseModel):
    status_id: str = Field(..., alias="statusId")
    device_id: str = Field(..., alias="deviceId")
    recorded_at: datetime
    current_pressure: Optional[float] = None
    battery_percentage: Optional[float] = None
    storage_available: Optional[int] = None
    memory_available: Optional[int] = None
    uptime: Optional[int] = None
    device_status: DeviceStatusEnum
    error_flags: Optional[str] = None
    firmware_version: Optional[str] = None
    temperature: Optional[float] = None
    humidity: Optional[float] = None
    signal_strength: Optional[int] = None

    class Config:
        orm_mode = True

class DeviceStatusHistoryResponse(BaseModel):
    status_history: List[DeviceStatusRecordResponse] = Field(...)

class DeviceGroupCreate(BaseModel):
    name: str
    firmware_update_priority: FirmwareDeploymentStageEnum = FirmwareDeploymentStageEnum.PRODUCTION # Default to production

class DeviceGroupResponse(BaseModel):
    group_id: str
    name: str
    organization_id: str
    firmware_update_priority: FirmwareDeploymentStageEnum
    created_at: datetime
    last_modified: datetime

    class Config:
        orm_mode = True 

class FirmwareCreate(BaseModel):
    version: str
    file_path: str
    deployment_stage: FirmwareDeploymentStageEnum

    @validator('version')
    def validate_version(cls, value):
        if not re.match(r'^\d+\.\d+\.\d+$', value):
            raise ValueError('Invalid firmware version format. Use major.minor.patch')
        return value

    @validates('file_path')
    def validate_file_path(self, key, file_path):
        # Validate that the file path is a proper path format
        if not os.path.isabs(file_path):
            raise ValueError('Invalid file path. An absolute path is required.')
        return file_path

class FirmwareResponse(BaseModel):
    firmware_id: str
    version: str
    file_path: str
    deployment_stage: FirmwareDeploymentStageEnum
    created_at: datetime

    class Config:
        orm_mode = True 

# User Endpoints
@app.post("/users/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Registers a new user."""
    try:
        existing_user = db.query(User).filter(User.username == user.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        # Hash the password before saving
        new_user = User(
            username=user.username,
            email=user.email,
            phone_number=user.phone_number,
            password=pwd_context.hash(user.password),
            first_name=user.first_name,
            last_name=user.last_name,
            address=user.address
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")  # Add this line for logging the error
        raise HTTPException(status_code=500, detail=f"Error registering user: {e}")

@app.post("/token", response_model=dict)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Generates an access token for a user."""
    return await authenticate_user(db, form_data)

@app.get("/users/me", response_model=UserResponse)
async def get_current_user_data(current_user: User = Depends(get_current_user)):
    """Returns data for the currently authenticated user."""
    return current_user

# Organization Endpoints
@app.post("/organizations", response_model=OrganizationResponse)
async def create_organization(organization: OrganizationCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Creates a new organization with the current user as owner."""
    print(current_user)
    print(organization)
    new_organization = Organization(
        name=organization.name,
        address=organization.address,
        owner_id=current_user.user_id
    )
    db.add(new_organization)
    db.commit()
    db.refresh(new_organization)

    # Update User organization id
    current_user.organization_id = new_organization.org_id
    db.commit()
    db.refresh(current_user)
    
    return new_organization

@app.get("/organizations/{org_id}", response_model=OrganizationResponse)
async def get_organization(org_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Gets an organization by its ID."""
    organization = db.query(Organization).filter(Organization.org_id == org_id).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    return organization

@app.get("/organizations", response_model=List[OrganizationResponse])
async def get_organizations(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Gets all organizations the current user owns or belongs to."""
    owned_orgs = db.query(Organization).filter(Organization.owner_id == current_user.user_id).all()
    member_orgs = db.query(Organization).join(User, Organization.users).filter(User.user_id == current_user.user_id).all()
    return owned_orgs + member_orgs

@app.put("/organizations/{org_id}")
async def update_organization(org_id: str, organization: OrganizationCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Updates an organization."""
    existing_org = db.query(Organization).filter(Organization.org_id == org_id).first()
    if not existing_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if existing_org.owner_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="You are not authorized to edit this organization")
    existing_org.name = organization.name
    existing_org.address = organization.address
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Organization updated successfully"})

@app.delete("/organizations/{org_id}")
async def delete_organization(org_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Deletes an organization."""
    existing_org = db.query(Organization).filter(Organization.org_id == org_id).first()
    if not existing_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if existing_org.owner_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="You are not authorized to delete this organization")
    db.delete(existing_org)
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Organization deleted successfully"})

# Device Endpoints
@app.post("/devices", response_model=AutoTQResponse)
async def create_device(device: AutoTQCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Creates a new device for the current user."""
    # Automatically assign organization ID
    organization = db.query(Organization).filter(Organization.owner_id == current_user.user_id).first()
    if not organization:
        raise HTTPException(status_code=400, detail="You need to belong to an organization to create a device")
    print(device.device_group_id)
    new_device = AutoTQ(
        mac_address=device.mac_address,
        serial_number=device.serial_number,
        human_readable_name=device.human_readable_name,
        auto_update_enabled=device.auto_update_enabled,
        owner_id=current_user.user_id,
        organization_id=organization.org_id,
        device_group_id=device.device_group_id
    )
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    return new_device

@app.get("/devices/{device_id}", response_model=AutoTQResponse)
async def get_device(device_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Gets a device by its ID."""
    device = db.query(AutoTQ).filter(AutoTQ.device_id == device_id).first()
    print(device)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # Check if the user owns the device or is in the organization
    if device.owner_id != current_user.user_id and device.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="You are not authorized to access this device")
    return device

@app.get("/devices", response_model=List[AutoTQResponse])
async def get_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Gets all devices owned by the current user."""
    devices = db.query(AutoTQ).filter(AutoTQ.owner_id == current_user.user_id).all()
    return devices

@app.put("/devices/{device_id}")
async def update_device(device_id: str, device: AutoTQCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Updates a device."""
    existing_device = db.query(AutoTQ).filter(AutoTQ.device_id == device_id).first()
    if not existing_device:
        raise HTTPException(status_code=404, detail="Device not found")
    if existing_device.owner_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="You are not authorized to edit this device")
    existing_device.mac_address = device.mac_address
    existing_device.serial_number = device.serial_number
    existing_device.human_readable_name = device.human_readable_name
    existing_device.firmware_id = device.firmware_id
    existing_device.auto_update_enabled = device.auto_update_enabled
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Device updated successfully"})

@app.delete("/devices/{device_id}")
async def delete_device(device_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Deletes a device."""
    existing_device = db.query(AutoTQ).filter(AutoTQ.device_id == device_id).first()
    if not existing_device:
        raise HTTPException(status_code=404, detail="Device not found")
    if existing_device.owner_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="You are not authorized to delete this device")
    db.delete(existing_device)
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Device deleted successfully"})

# Device Group Endpoints
@app.post("/device-groups", response_model=DeviceGroupResponse)
async def create_device_group(device_group: DeviceGroupCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Creates a new device group for the current user's organization."""
    # Automatically assign organization ID
    organization = db.query(Organization).filter(Organization.owner_id == current_user.user_id).first()
    if not organization:
        raise HTTPException(status_code=400, detail="You need to belong to an organization to create a device group")
    new_group = DeviceGroup(
        name=device_group.name,
        organization_id=organization.org_id,
        firmware_update_priority=device_group.firmware_update_priority
    )
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return new_group

@app.get("/device-groups/{group_id}", response_model=DeviceGroupResponse)
async def get_device_group(group_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Gets a device group by its ID."""
    device_group = db.query(DeviceGroup).filter(DeviceGroup.group_id == group_id).first()
    if not device_group:
        raise HTTPException(status_code=404, detail="Device group not found")
    # Check if the user is in the organization
    if device_group.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="You are not authorized to access this device group")
    return device_group

@app.get("/device-groups", response_model=List[DeviceGroupResponse])
async def get_device_groups(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Gets all device groups within the current user's organization."""
    device_groups = db.query(DeviceGroup).filter(DeviceGroup.organization_id == current_user.organization_id).all()
    print(device_groups)
    return device_groups

@app.put("/device-groups/{group_id}")
async def update_device_group(group_id: str, device_group: DeviceGroupCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Updates a device group."""
    existing_device_group = db.query(DeviceGroup).filter(DeviceGroup.group_id == group_id).first()
    if not existing_device_group:
        raise HTTPException(status_code=404, detail="Device group not found")
    # Check if the user is in the organization
    if existing_device_group.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="You are not authorized to edit this device group")
    existing_device_group.name = device_group.name
    existing_device_group.firmware_update_priority = device_group.firmware_update_priority
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Device group updated successfully"})

@app.delete("/device-groups/{group_id}")
async def delete_device_group(group_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Deletes a device group."""
    existing_device_group = db.query(DeviceGroup).filter(DeviceGroup.group_id == group_id).first()
    if not existing_device_group:
        raise HTTPException(status_code=404, detail="Device group not found")
    # Check if the user is in the organization
    if existing_device_group.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="You are not authorized to delete this device group")
    db.delete(existing_device_group)
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Device group deleted successfully"})

# Device Status Endpoints
@app.get("/devices/{device_id}/status", response_model=DeviceStatusRecordResponse)
async def get_latest_device_status(device_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Gets the latest status record for a device."""
    device = db.query(AutoTQ).filter(AutoTQ.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # Check if the user owns the device or is in the organization
    if device.owner_id != current_user.user_id and device.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="You are not authorized to access this device")
    return device.latest_status

@app.get("/devices/{device_id}/status-history", response_model=DeviceStatusHistoryResponse)
async def get_device_status_history(device_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Gets all status records for a device."""
    device = db.query(AutoTQ).filter(AutoTQ.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # Check if the user owns the device or is in the organization
    if device.owner_id != current_user.user_id and device.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="You are not authorized to access this device")
    return {"status_history": [DeviceStatusRecordResponse.from_orm(record) for record in device.status_history]}

# Firmware Endpoints
@app.post("/firmware", response_model=FirmwareResponse)
async def create_firmware(firmware: FirmwareCreate, db: Session = Depends(get_db)):
    """Creates a new firmware version."""
    new_firmware = Firmware(
        version=firmware.version,
        file_path=firmware.file_path,
        deployment_stage=firmware.deployment_stage
    )
    db.add(new_firmware)
    db.commit()
    db.refresh(new_firmware)
    return new_firmware

@app.get("/firmware/{firmware_id}", response_model=FirmwareResponse)
async def get_firmware(firmware_id: str, db: Session = Depends(get_db)):
    """Gets a firmware version by its ID."""
    firmware = db.query(Firmware).filter(Firmware.firmware_id == firmware_id).first()
    if not firmware:
        raise HTTPException(status_code=404, detail="Firmware not found")
    return firmware

@app.get("/firmware", response_model=List[FirmwareResponse])
async def get_firmwares(db: Session = Depends(get_db)):
    """Gets all firmware versions."""
    firmwares = db.query(Firmware).all()
    return firmwares

@app.put("/firmware/{firmware_id}")
async def update_firmware(firmware_id: str, firmware: FirmwareCreate, db: Session = Depends(get_db)):
    """Updates a firmware version."""
    print(firmware_id)
    existing_firmware = db.query(Firmware).filter(Firmware.firmware_id == firmware_id).first()
    if not existing_firmware:
        raise HTTPException(status_code=404, detail="Firmware not found")
    existing_firmware.version = firmware.version
    existing_firmware.file_path = firmware.file_path
    existing_firmware.deployment_stage = firmware.deployment_stage
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Firmware updated successfully"})

@app.delete("/firmware/{firmware_id}")
async def delete_firmware(firmware_id: str, db: Session = Depends(get_db)):
    """Deletes a firmware version."""
    existing_firmware = db.query(Firmware).filter(Firmware.firmware_id == firmware_id).first()
    if not existing_firmware:
        raise HTTPException(status_code=404, detail="Firmware not found")
    db.delete(existing_firmware)
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Firmware deleted successfully"})

# Firmware Upload Endpoint
@app.post("/firmware/upload")
async def upload_firmware(
    version: str = Form(...),
    deployment_stage: str = Form(...),
    file: UploadFile = File(...)
):
    """Uploads a new firmware version."""
    # Create a directory for the firmware version if it doesn't exist
    firmware_dir = os.path.join('firmware', version)
    os.makedirs(firmware_dir, exist_ok=True)

    # Save the firmware file
    file_path = os.path.join(firmware_dir, file.filename)
    with open(file_path, 'wb') as f:
        f.write(await file.read())

    # Create and store the firmware record in the database
    db = next(get_db())
    new_firmware = Firmware(
        version=version,
        file_path=f'C:/Users/gator/Documents/Develop/GoldenHourMedical/GoldenHourRegistry/firmware/{version}/{file.filename}', 
        deployment_stage=FirmwareDeploymentStageEnum[deployment_stage.upper()]
    )
    db.add(new_firmware)
    db.commit()
    db.refresh(new_firmware)
    return {"message": "Firmware uploaded successfully", "firmware_id": new_firmware.firmware_id}

@app.get("/firmware/{firmware_id}/download")
async def download_firmware(firmware_id: str, db: Session = Depends(get_db)):
    """Downloads a firmware binary file."""
    firmware = db.query(Firmware).filter(Firmware.firmware_id == firmware_id).first()
    if not firmware:
        raise HTTPException(status_code=404, detail="Firmware not found")

    file_path = firmware.file_path
    print(file_path)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Firmware file not found")
    print(file_path)
    with open(file_path, 'rb') as f:
        file_content = f.read()

    return Response(content=file_content, media_type="application/octet-stream", headers={'Content-Disposition': f'attachment; filename="{os.path.basename(file_path)}"'})

# Endpoint for checking if a firmware update is needed
@app.get("/devices/{device_id}/firmware-update-needed")
async def check_firmware_update(device_id: str, db: Session = Depends(get_db)):
    """Checks if a firmware update is needed for the given device."""
    # Query to join AutoTQ and DeviceGroup tables based on device_group_id
    device_with_group = (
        db.query(AutoTQ, DeviceGroup)
        .join(DeviceGroup, AutoTQ.device_group_id == DeviceGroup.group_id)
        .filter(AutoTQ.device_id == device_id)
        .first()
    )

    if not device_with_group:
        raise HTTPException(status_code=404, detail="Device or Device group not found")

    device, device_group = device_with_group

    # Get the rank of the firmware update priority
    priority_rank = 0
    if device_group.firmware_update_priority == FirmwareDeploymentStageEnum.PROTOTYPE:
        priority_rank = 1
    elif device_group.firmware_update_priority == FirmwareDeploymentStageEnum.BETA:
        priority_rank = 2
    elif device_group.firmware_update_priority == FirmwareDeploymentStageEnum.RELEASE_CANDIDATE:
        priority_rank = 3
    elif device_group.firmware_update_priority == FirmwareDeploymentStageEnum.PRODUCTION:
        priority_rank = 4


    # Map the deployment stages to their corresponding ranks
    deployment_stage_rank = case(
        (Firmware.deployment_stage == FirmwareDeploymentStageEnum.PROTOTYPE, 1),
        (Firmware.deployment_stage == FirmwareDeploymentStageEnum.BETA, 2),
        (Firmware.deployment_stage == FirmwareDeploymentStageEnum.RELEASE_CANDIDATE, 3),
        (Firmware.deployment_stage == FirmwareDeploymentStageEnum.PRODUCTION, 4),
        else_=0
    )

    # Find the highest version firmware that meets the priority rank
    available_firmware = (
        db.query(Firmware)
        .filter(deployment_stage_rank >= priority_rank)
        .order_by(Firmware.version.desc())
        .all()
    )

    if not available_firmware:
        return {"needed": False}

    # Find the highest version firmware that is higher than the current version
    current_firmware = db.query(Firmware).filter(Firmware.firmware_id == device.current_firmware_id).first()
    if current_firmware:
        for firmware in available_firmware:
            if firmware.version > current_firmware.version:
                return {"needed": True, "firmware_id": str(firmware.firmware_id)}
    else:
        return {"needed": True, "firmware_id": str(available_firmware[0].firmware_id)}

    return {"needed": False}

@app.get("/devices/mac/{mac_address}", response_model=dict)
async def get_device_by_mac(mac_address: str, db: Session = Depends(get_db)):
    """Gets a device by its MAC address."""
    device = db.query(AutoTQ).filter(AutoTQ.mac_address == mac_address).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"device_id": device.device_id}  # Only return the device ID

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)