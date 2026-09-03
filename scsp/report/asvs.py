"""OWASP ASVS 5.0 chapter definitions for coverage matrix."""

ASVS_CHAPTERS = [
    {"id": "V1", "title": "Encoding and Sanitization", "testable": True},
    {"id": "V2", "title": "Validation and Business Logic", "testable": False},
    {"id": "V3", "title": "Web Frontend Security", "testable": True},
    {"id": "V4", "title": "API and Web Service", "testable": True},
    {"id": "V5", "title": "File Handling", "testable": True},
    {"id": "V6", "title": "Authentication", "testable": True},
    {"id": "V7", "title": "Session Management", "testable": True},
    {"id": "V8", "title": "Authorization", "testable": False},
    {"id": "V9", "title": "Self-contained Tokens", "testable": True},
    {"id": "V10", "title": "OAuth and OIDC", "testable": False},
    {"id": "V11", "title": "Cryptography at Rest", "testable": True},
    {"id": "V12", "title": "Secure Communication", "testable": True},
    {"id": "V13", "title": "Configuration", "testable": True},
    {"id": "V14", "title": "Data Protection", "testable": False},
    {"id": "V15", "title": "Secure Coding and Architecture", "testable": True},
    {"id": "V16", "title": "Security Logging", "testable": True},
    {"id": "V17", "title": "WebRTC and Emerging", "testable": False},
]

LANE_TO_CHAPTERS = {
    "fast": ["V1", "V3", "V4", "V16"],
    "supply_chain": ["V5", "V13", "V15"],
    "secrets": ["V6", "V9"],
    "iac": ["V13"],
    "behavioral": ["V13", "V15"],
    "fuzz": ["V15"],
    "git_forensics": ["V15"],
    "crypto": ["V11", "V12"],
    "wasm": ["V5"],
    "hidden": ["V13", "V15"],
    "campaign": ["V15"],
    "fusion": ["V1", "V4"],
}
