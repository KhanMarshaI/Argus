# Argus: Threat Intelligence Aggregator  

Argus is a comprehensive threat intelligence tool designed to analyze and manage file and URL scans with ease. Integrating APIs like VirusTotal, it streamlines the process of threat analysis while providing user-friendly interfaces and administrative controls. It is a WIP.

## 🚀 Features  

### 🔍 **Dashboard**  
- Displays the 10 most recent URL and file scans.  
- Provides a quick summary of total URLs and files analyzed.  
![image](https://github.com/user-attachments/assets/5f7a6844-f062-4ce0-ba24-ae044e39f88f)

### 📊 **Overview**  
- Access a complete list of all file and URL scan entries stored in the database.  
![image](https://github.com/user-attachments/assets/f0b77b69-9982-4902-a2f9-71de8c205569)

### 🖼️ **File Hash Scanner**  
- Perform file hash scans using:  
  - **VirusTotal API**: Query VirusTotal for threat analysis.  
  - **Local Database**: Retrieve results locally for efficiency.  
- Toggleable JSON response for detailed insights.  
- Automatically saves scan results to the database.  
![image](https://github.com/user-attachments/assets/2559babe-7964-429a-afdc-5777bb5a3b70)


### 🌐 **URL Analysis**  
- Analyze URLs via:  
  - **VirusTotal API**: Query URL threat data.  
  - **Local Database**: Store and retrieve scan results.  
- Provides streamlined analysis without JSON output.  
![image](https://github.com/user-attachments/assets/7af62d28-8619-465d-9471-865c30a21d81)


### 📂 **File Upload**  
- Upload files directly to VirusTotal for analysis.  
- Automatically stores scan results in the database.  
![image](https://github.com/user-attachments/assets/373912dd-fc5b-407d-9c1e-b7effff618c2)


### ⚙️ **Administrative Actions**  
- **Custom File Hash Reports**:  
  - Create reports based on results from engines.  
- **Custom URL Analysis Reports**:  
  - Create and update detailed URL analysis reports.  
- **User and Admin Management**:  
  - Register and manage users and administrators.  
- **Logging Tables**:  
  - Maintain logs for all key activities for auditing and troubleshooting.  
![image](https://github.com/user-attachments/assets/7dfeb220-be57-46b5-a258-a9f8fa8eb9a6)


---

## 🛠️ Technology Stack  

- **Frontend**: .NET Blazor
- **Backend**: .NET CORE WEB API  
- **Database**: Azure SQL Database/MSSQL  
- **APIs Integrated**:  
  - VirusTotal (for now) 

## 🎯 Goals  

Argus aims to:  
1. Simplify threat intelligence for organizations and cybersecurity enthusiasts.  
2. Provide secure, scalable, and easily manageable tools for threat detection.  
3. Enable both novice and experienced users to perform in-depth threat analysis.  

---

## 📋 Setup Instructions  

### Prerequisites  
1. .NET 8 installed.  
2. Access to Azure SQL Database/MSSQL.  
3. API keys for VirusTotal.  

### Steps to Install  
1. Clone this repository.  
   ```bash  
   git clone https://github.com/KhanMarshaI/argus.git
   ```
2. Open the project in Visual Studio.
3. Configure the database connection strings in Services folder.
4. Run the project.

---

## 📫 Contact
Feel free to reach out if you have any questions or suggestions:

Email: iamtaha05@gmail.com
LinkedIn: https://www.linkedin.com/in/mtahakhan05/

---
