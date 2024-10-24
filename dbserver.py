from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, ForeignKey, Enum, Table
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import enum
from datetime import datetime
import uuid
import os
import json
from sqlalchemy.orm import validates
import re

Base = declarative_base()

SessionLocal = sessionmaker(autocommit=False, autoflush=False)

class DeviceStatusEnum(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    MAINTENANCE = "maintenance"
    UPDATING = "updating"

class FirmwareDeploymentStageEnum(enum.Enum):
    PROTOTYPE = "prototype"
    BETA = "beta"
    RELEASE_CANDIDATE = "release candidate"
    PRODUCTION = "production"

# Association tables for many-to-many relationships
org_admins = Table('org_admins', Base.metadata,
    Column('organization_id', String, ForeignKey('organizations.org_id')),
    Column('user_id', String, ForeignKey('users.user_id'))
)

org_users = Table('org_users', Base.metadata,
    Column('organization_id', String, ForeignKey('organizations.org_id')),
    Column('user_id', String, ForeignKey('users.user_id'))
)

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String, unique=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    phone_number = Column(String(20), unique=True, nullable=False)
    password = Column(String(255), nullable=False)  # Should store hashed password only
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    address = Column(String(500), nullable=False)
    organization_id = Column(String, ForeignKey('organizations.org_id'))
    
    created_at = Column(DateTime, default=datetime.utcnow)
    last_modified = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    owned_org = relationship("Organization", foreign_keys="Organization.owner_id", back_populates="owner")
    organization = relationship("Organization", foreign_keys=[organization_id], back_populates="users")
    owned_devices = relationship("AutoTQ", back_populates="owner")

    @validates('email')
    def validate_email(self, key, email):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError('Invalid email address')
        return email

    @validates('phone_number')
    def validate_phone(self, key, phone):
        # Remove any non-digit characters for validation
        clean_phone = re.sub(r'\D', '', phone)
        if not 10 <= len(clean_phone) <= 15:  # Accept international numbers
            raise ValueError('Invalid phone number length')
        return phone

    @validates('username')
    def validate_username(self, key, username):
        if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
            raise ValueError('Username must be 3-50 characters long and contain only letters, numbers, and underscores')
        return username

class Organization(Base):
    __tablename__ = 'organizations'
    
    id = Column(Integer, primary_key=True)
    org_id = Column(String, unique=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False)
    address = Column(String(500), nullable=False)
    owner_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    last_modified = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    owner = relationship("User", foreign_keys=[owner_id], back_populates="owned_org")
    users = relationship("User", foreign_keys="User.organization_id", back_populates="organization")
    admins = relationship("User", secondary=org_admins, backref="admin_of")
    normal_users = relationship("User", secondary=org_users, backref="member_of")
    devices = relationship("AutoTQ", back_populates="organization")
    device_groups = relationship("DeviceGroup", back_populates="organization")

class AutoTQ(Base):
    __tablename__ = 'autotq_devices'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(String, unique=True, default=lambda: str(uuid.uuid4()))
    mac_address = Column(String(17), unique=True, nullable=False)
    serial_number = Column(String(100), unique=True, nullable=False)
    human_readable_name = Column(String(200), nullable=False)
    
    owner_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    organization_id = Column(String, ForeignKey('organizations.org_id'), nullable=False)
    device_group_id = Column(String, ForeignKey('device_groups.group_id'))
    latest_status_id = Column(String, ForeignKey('device_statuses.status_id'))
    current_firmware_id = Column(String, ForeignKey('firmwares.firmware_id'))  # Reference to Firmware
    
    auto_update_enabled = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    last_modified = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    training_completed_at = Column(DateTime)
    order_placed_at = Column(DateTime)
    arrival_date = Column(DateTime)
    last_active_at = Column(DateTime)
    last_firmware_update = Column(DateTime)
    
    owner = relationship("User", back_populates="owned_devices")
    organization = relationship("Organization", back_populates="devices")
    device_group = relationship("DeviceGroup", back_populates="devices")
    latest_status = relationship("DeviceStatusRecord", 
                               foreign_keys=[latest_status_id],
                               uselist=False)
    status_history = relationship("DeviceStatusRecord",
                                primaryjoin="and_(AutoTQ.device_id==DeviceStatusRecord.device_id, "
                                          "AutoTQ.device_id!=DeviceStatusRecord.status_id)",
                                back_populates="device")
    current_firmware = relationship("Firmware", foreign_keys=[current_firmware_id], uselist=False)

class DeviceGroup(Base):
    __tablename__ = 'device_groups'
    
    id = Column(Integer, primary_key=True)
    group_id = Column(String, unique=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False)
    organization_id = Column(String, ForeignKey('organizations.org_id'), nullable=False)
    firmware_update_priority = Column(Enum(FirmwareDeploymentStageEnum), nullable=False) # Add the firmware update priority
    
    created_at = Column(DateTime, default=datetime.utcnow)
    last_modified = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    organization = relationship("Organization", back_populates="device_groups")
    devices = relationship("AutoTQ", back_populates="device_group")

class DeviceStatusRecord(Base):
    __tablename__ = 'device_statuses'
    
    id = Column(Integer, primary_key=True)
    status_id = Column(String, unique=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String, ForeignKey('autotq_devices.device_id'), nullable=False)
    
    recorded_at = Column(DateTime, default=datetime.utcnow)
    current_pressure = Column(Float)
    battery_percentage = Column(Float)
    storage_available = Column(Integer)  # in bytes
    memory_available = Column(Integer)  # in bytes
    uptime = Column(Integer)  # in seconds
    device_status = Column(Enum(DeviceStatusEnum), nullable=False)
    error_flags = Column(String)  # Store array as JSON string
    firmware_version = Column(String(50))
    
    temperature = Column(Float)
    humidity = Column(Float)
    signal_strength = Column(Integer)
    
    device = relationship("AutoTQ",
                         foreign_keys=[device_id],
                         back_populates="status_history")
class Firmware(Base):
    __tablename__ = 'firmwares'
    
    id = Column(Integer, primary_key=True)
    firmware_id = Column(String, unique=True, default=lambda: str(uuid.uuid4()), nullable=False)
    version = Column(String(50), nullable=False)
    major_version = Column(Integer)
    minor_version = Column(Integer)
    patch_version = Column(Integer)
    file_path = Column(String(255), nullable=False)  # Changed from url to file_path
    deployment_stage = Column(Enum(FirmwareDeploymentStageEnum), nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    def __init__(self, version, file_path, deployment_stage, major_version=None, minor_version=None, patch_version=None):
        self.firmware_id = str(uuid.uuid4())  # Generate a new UUID for firmware_id
        self.version = version
        self.file_path = file_path  # Store the file path
        self.deployment_stage = deployment_stage

        # Set default versions if not provided
        if major_version is None or minor_version is None or patch_version is None:
            # Parse the version string to get major, minor, patch values
            version_parts = version.split('.')
            self.major_version = int(version_parts[0]) if len(version_parts) > 0 else 0
            self.minor_version = int(version_parts[1]) if len(version_parts) > 1 else 0
            self.patch_version = int(version_parts[2]) if len(version_parts) > 2 else 0
        else:
            self.major_version = major_version
            self.minor_version = minor_version
            self.patch_version = patch_version

    @validates('version')
    def validate_version(self, key, version):
        if not re.match(r'^\d+\.\d+\.\d+$', version):
            raise ValueError('Invalid firmware version format. Use major.minor.patch')
        return version

    @validates('file_path')
    def validate_file_path(self, key, file_path):
        # Validate that the file path is a proper path format
        if not os.path.isabs(file_path):
            raise ValueError('Invalid file path. An absolute path is required.')
        return file_path

    # @validates('deployment_stage')
    # def validate_deployment_stage(self, key, stage):
    #     valid_stages = ["prototype", "beta", "release candidate", "production"]
    #     if stage.lower() not in valid_stages:
    #         raise ValueError(f"Invalid deployment stage. Valid options: {', '.join(valid_stages)}")
    #     return stage

def init_db(db_path='autotq.db'):
    """Initialize the SQLite database"""
    # Create database directory if it doesn't exist
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    # Create database and tables
    database_url = f'sqlite:///{db_path}'
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    
    # Create session factory
    Session = sessionmaker(bind=engine)
    return engine, Session

def create_test_data(session):
    """Create some test data in the database"""
    # Create a test user
    test_user = User(
        username="johndoe",
        email="john.doe@example.com",
        phone_number="+1-555-123-4567",
        password="hashed_password_here",  # In practice, this should be properly hashed
        first_name="John",
        last_name="Doe",
        address="123 Main St"
    )
    session.add(test_user)
    session.flush()  # Flush to get the user ID

    # Create a test organization
    test_org = Organization(
        name="Acme Corp",
        address="456 Elm St",
        owner_id=test_user.user_id
    )
    session.add(test_org)
    session.flush()

    # Create a test device
    test_device = AutoTQ(
        mac_address="AA:BB:CC:DD:EE:FF",
        serial_number="1234567890",
        human_readable_name="Device 1",
        owner_id=test_user.user_id,
        organization_id=test_org.org_id
    )
    session.add(test_device)
    session.flush()

    # Create a test status record
    test_status = DeviceStatusRecord(
        device_id=test_device.device_id,
        current_pressure=100.0,
        battery_percentage=80.0,
        device_status=DeviceStatusEnum.ACTIVE
    )
    session.add(test_status)
    session.flush()

    # Create a test firmware
    test_firmware = Firmware(
        version="1.2.3",
        file_path="/path/to/firmware/v1.2.3.bin", # Using a file path
        deployment_stage=FirmwareDeploymentStageEnum.PRODUCTION 
    )
    session.add(test_firmware)
    session.flush()

    # Assign firmware to the device
    test_device.current_firmware_id = test_firmware.firmware_id

    # Create a test device group
    test_group = DeviceGroup(
        name="Test Group",
        organization_id=test_org.org_id,
        firmware_update_priority=FirmwareDeploymentStageEnum.BETA
    )
    session.add(test_group)
    session.flush()

    # Assign the device to the group
    test_device.device_group_id = test_group.group_id

    session.commit()
    return test_user, test_org, test_device, test_status, test_firmware, test_group

def print_database_state(session):
    """Print the current state of the database"""
    print("\n=== Database State ===")
    
    print("\nUsers:")
    users = session.query(User).all()
    for user in users:
        print(f"- {user.first_name} {user.last_name} (ID: {user.id})")
        print(f"  UUID: {user.user_id}")
        print(f"  Username: {user.username}")
        print(f"  Email: {user.email}")
        print(f"  Phone: {user.phone_number}")
        print(f"  Address: {user.address}")

if __name__ == "__main__":
    # Initialize the database
    print("Initializing database...")
    engine, Session = init_db()
    session = Session()
    
    try:
        # Create test data
        print("Creating test data...")
        # test_user, test_org, test_device, test_status, test_firmware, test_group = create_test_data(session)
        
        # Print the database state
        print_database_state(session)
        
        print("\nDatabase setup completed successfully!")
        
    except Exception as e:
        print(f"Error during database setup: {e}")
        session.rollback()
    finally:
        session.close()