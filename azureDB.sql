use argus;

create table FileReports(
ID INT PRIMARY KEY IDENTITY(1,1),
FileHashSHA NVARCHAR(64) NOT NULL UNIQUE,
FileID NVARCHAR(64),
FileType NVARCHAR(32), 
FileExtension NVARCHAR(16),
Magic NVARCHAR(100),
Reputation INT,
Malicious INT,
Suspicious INT,
Harmless INT,
Undetected INT,
AnalyzedNames NVARCHAR(MAX),
CreatedAt DATETIME DEFAULT GETDATE()
);

CREATE TABLE FileSignatures(
SignatureID INT PRIMARY KEY IDENTITY(1001,1),
FileReportID INT NOT NULL, -- Foreign Key
MD5 NVARCHAR(32),
SHA1 NVARCHAR(40), 
SHA256 NVARCHAR(64),
TLSH  NVARCHAR(72),
VHASH NVARCHAR(55),
FOREIGN KEY (FileReportID) REFERENCES FileReports(ID) ON DELETE CASCADE
);

SELECT * FROM FileReports;

SELECT * FROM FileReports fr
JOIN FileSignatures fs ON fr.ID = fs.FileReportID ;

SELECT * FROM authorized_users;
DELETE FROM authorized_users WHERE authUserID = 5;

CREATE Table Analysis(
AnalysisID VARCHAR(100) Primary Key,
Type Varchar(12),
Status Varchar(20),
Malicious INT,
Suspicious INT,
Undetected INT,
Harmless INT,
);

CREATE TABLE URLAnalysis(
URLID int primary key identity(2000, 1),
URL VARCHAR(255) NOT NULL,
AnalysisID VARCHAR(100) FOREIGN KEY References Analysis(AnalysisID),
CreatedAT DATE DEFAULT GETDATE()
);

SELECT * FROM URLAnalysis u JOIN Analysis a ON u.AnalysisID = a.AnalysisID;