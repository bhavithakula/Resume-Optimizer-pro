PRAGMA foreign_keys = ON;

-- USER_AUTH TABLE (Separate authentication table)
CREATE TABLE IF NOT EXISTS user_auth (
    auth_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    last_failed_login DATETIME,
    password_reset_token TEXT,
    password_reset_expires DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- USERS TABLE (Enhanced with profile data only)
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    full_name TEXT,
    phone TEXT,
    profile_picture TEXT,
    bio TEXT,
    linkedin_url TEXT,
    github_url TEXT,
    website_url TEXT,
    location TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_active BOOLEAN DEFAULT 1,
    email_verified BOOLEAN DEFAULT 0,
    premium_user BOOLEAN DEFAULT 0
);

-- USER_ANALYTICS TABLE (Track user behavior and access)
CREATE TABLE IF NOT EXISTS user_analytics (
    analytics_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL, -- login, logout, upload_resume, download_pdf, download_docx, apply_job, etc.
    event_data TEXT, -- JSON data with additional details
    ip_address TEXT,
    user_agent TEXT,
    page_url TEXT,
    session_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- SITE_ANALYTICS TABLE (Track all site access regardless of login)
CREATE TABLE IF NOT EXISTS site_analytics (
    site_analytics_id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_id TEXT, -- Generated UUID for tracking
    ip_address TEXT,
    user_agent TEXT,
    page_url TEXT,
    referrer TEXT,
    country TEXT,
    city TEXT,
    device_type TEXT, -- mobile, desktop, tablet
    browser TEXT,
    os TEXT,
    session_duration INTEGER, -- in seconds
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- COMPANIES TABLE
CREATE TABLE IF NOT EXISTS companies (
    company_id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT UNIQUE NOT NULL,
    industry TEXT,
    website TEXT,
    location TEXT,
    company_size TEXT,
    logo_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- JOB_APPLICATIONS TABLE (Enhanced with more tracking)
CREATE TABLE IF NOT EXISTS job_applications (
    application_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    company_id INTEGER,
    job_title TEXT NOT NULL,
    job_description TEXT,
    job_url TEXT,
    application_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    application_status TEXT DEFAULT 'Applied', -- Applied, Interview, Rejected, Offered, Accepted
    priority_level TEXT DEFAULT 'Medium', -- High, Medium, Low
    salary_range TEXT,
    job_location TEXT,
    job_type TEXT, -- Full-time, Part-time, Contract, Remote
    application_source TEXT, -- LinkedIn, Indeed, Company website, etc.
    application_deadline DATETIME,
    follow_up_date DATETIME,
    interview_date DATETIME,
    notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (company_id) REFERENCES companies(company_id)
);

-- RESUMES TABLE (Enhanced)
CREATE TABLE IF NOT EXISTS resumes (
    resume_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    application_id INTEGER,
    resume_title TEXT,
    original_text TEXT,
    optimized_text TEXT,
    ats_score REAL,
    file_path TEXT,
    file_size INTEGER,
    is_primary BOOLEAN DEFAULT 0, -- Mark primary resume
    version_number INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (application_id) REFERENCES job_applications(application_id)
);

-- OPTIMIZATION_RESULTS TABLE (Enhanced with detailed metrics)
CREATE TABLE IF NOT EXISTS optimization_results (
    optimization_id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER,
    resume_id INTEGER,
    ats_score_before REAL,
    ats_score_after REAL,
    improvement_percentage REAL,
    matching_keywords INTEGER,
    total_keywords INTEGER,
    keyword_density REAL,
    missing_keywords TEXT, -- JSON array
    added_keywords TEXT, -- JSON array
    optimization_suggestions TEXT,
    optimization_version INTEGER DEFAULT 1,
    processing_time_seconds REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES job_applications(application_id),
    FOREIGN KEY (resume_id) REFERENCES resumes(resume_id)
);

-- USER_SESSIONS TABLE (Enhanced session management)
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- APPLICATION_TIMELINE TABLE (Track application progress)
CREATE TABLE IF NOT EXISTS application_timeline (
    timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER,
    status_change TEXT, -- Applied, Interview Scheduled, Interview Completed, etc.
    previous_status TEXT,
    notes TEXT,
    reminder_date DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES job_applications(application_id)
);

-- DOWNLOAD_HISTORY TABLE (Track resume downloads)
CREATE TABLE IF NOT EXISTS download_history (
    download_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    application_id INTEGER,
    resume_id INTEGER,
    download_format TEXT, -- pdf, docx
    file_size INTEGER,
    download_ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (application_id) REFERENCES job_applications(application_id),
    FOREIGN KEY (resume_id) REFERENCES resumes(resume_id)
);

-- SYSTEM_SETTINGS TABLE (Store app configuration)
CREATE TABLE IF NOT EXISTS system_settings (
    setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_name TEXT UNIQUE NOT NULL,
    setting_value TEXT,
    setting_type TEXT, -- string, integer, boolean, json
    description TEXT,
    is_public BOOLEAN DEFAULT 0,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- INDEXES for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_user_auth_email ON user_auth(email);
CREATE INDEX IF NOT EXISTS idx_user_auth_user_id ON user_auth(user_id);
CREATE INDEX IF NOT EXISTS idx_user_analytics_user ON user_analytics(user_id);
CREATE INDEX IF NOT EXISTS idx_user_analytics_event ON user_analytics(event_type);
CREATE INDEX IF NOT EXISTS idx_site_analytics_visitor ON site_analytics(visitor_id);
CREATE INDEX IF NOT EXISTS idx_applications_user ON job_applications(user_id);
CREATE INDEX IF NOT EXISTS idx_applications_company ON job_applications(company_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON job_applications(application_status);
CREATE INDEX IF NOT EXISTS idx_resumes_user ON resumes(user_id);
CREATE INDEX IF NOT EXISTS idx_resumes_application ON resumes(application_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_download_history_user ON download_history(user_id);

-- Insert default system settings
INSERT OR IGNORE INTO system_settings (setting_name, setting_value, setting_type, description, is_public) VALUES
('ats_target_score', '100', 'integer', 'Target ATS score after optimization', 1),
('max_upload_size_mb', '10', 'integer', 'Maximum file upload size in MB', 1),
('session_timeout_hours', '24', 'integer', 'Session timeout in hours', 0),
('enable_analytics', 'true', 'boolean', 'Enable user analytics tracking', 0),
('site_name', 'AB Resume Optimizer', 'string', 'Site display name', 1),
('admin_email', 'admin@abresumeoptimizer.com', 'string', 'Administrator email', 0); 