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

CREATE TABLE SignatureInfo (
    SignatureID INT PRIMARY KEY IDENTITY(2001, 1),
    FileReportID INT NOT NULL, -- Foreign Key
    Description NVARCHAR(255),
    FileVersion NVARCHAR(100),
    OriginalName NVARCHAR(100),
    Product NVARCHAR(100),
    InternalName NVARCHAR(100),
    Copyright NVARCHAR(255),
    FOREIGN KEY (FileReportID) REFERENCES FileReports(ID) ON DELETE CASCADE
);

CREATE TABLE AnalysisResults (
    AnalysisResultID INT PRIMARY KEY IDENTITY(3001, 1),
    FileReportID INT NOT NULL, -- Foreign Key
    EngineName NVARCHAR(100),
    Category NVARCHAR(50),
    Result NVARCHAR(255),
    FOREIGN KEY (FileReportID) REFERENCES FileReports(ID) ON DELETE CASCADE
);	

ALTER TABLE FileReports
ADD LastModificationDate DATETIME NULL;

SELECT * FROM FileReports;
SELECT * FROM FileSignatures;
SELECT * FROM SignatureInfo;
SELECT * FROM AnalysisResults;

SELECT * FROM FileReports fr
JOIN FileSignatures fs ON fr.ID = fs.FileReportID ;

SELECT fr.*, fs.*, si.*, ar.EngineName, ar.Category, ar.Result
FROM FileReports fr
LEFT JOIN FileSignatures fs ON fr.ID = fs.FileReportID
LEFT JOIN SignatureInfo si ON fr.ID = si.FileReportID
LEFT JOIN AnalysisResults ar ON fr.ID = ar.FileReportID

SELECT fr.*, fs.*, si.*, ar.EngineName, ar.Category, ar.Result
FROM FileReports fr
LEFT JOIN FileSignatures fs ON fr.ID = fs.FileReportID
LEFT JOIN SignatureInfo si ON fr.ID = si.FileReportID
LEFT JOIN AnalysisResults ar ON fr.ID = ar.FileReportID
WHERE fr.FileID = 2

ALTER TABLE FileSignatures DROP CONSTRAINT FK_FileSignatures_FileReports;
ALTER TABLE SignatureInfo DROP CONSTRAINT FK_SignatureInfo_FileReports;
ALTER TABLE AnalysisResults DROP CONSTRAINT FK_AnalysisResults_FileReports;

truncate table FileReports
truncate table FileSignatures
truncate table AnalysisResults
truncate table SignatureInfo;

ALTER TABLE FileSignatures ADD CONSTRAINT FK_FileSignatures_FileReports FOREIGN KEY (FileReportID) REFERENCES FileReports(ID) ON DELETE CASCADE;
ALTER TABLE SignatureInfo ADD CONSTRAINT FK_SignatureInfo_FileReports FOREIGN KEY (FileReportID) REFERENCES FileReports(ID) ON DELETE CASCADE;
ALTER TABLE AnalysisResults ADD CONSTRAINT FK_AnalysisResults_FileReports FOREIGN KEY (FileReportID) REFERENCES FileReports(ID) ON DELETE CASCADE;

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

ALTER TABLE URLAnalysis
DROP CONSTRAINT DF__URLAnalys__Creat__75A278F5;

ALTER table URLAnalysis Alter Column CreatedAT DATETIME;

ALTER TABLE URLAnalysis
ADD CONSTRAINT DF__URLAnalysis__CreatedAT
DEFAULT GETDATE() FOR CreatedAT;

SELECT * FROM URLAnalysis u JOIN Analysis a ON u.AnalysisID = a.AnalysisID ORDER BY u.CreatedAT DESC;


ALTER TABLE authorized_users ADD authLevel varchar(15);
select * from authorized_users;
UPDATE authorized_users SET authLevel = 'User'
UPDATE authorized_users SET authLevel = 'Administrator' where username = 'marshal'

DELETE FROM authorized_users WHERE authUserID = 8