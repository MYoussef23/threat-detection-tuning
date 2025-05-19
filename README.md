# Security Tuning and Automation Projects

This repository serves as a collection of security tuning requests, automation scripts, and project examples based on my experience in Security Operations and Business Systems Analysis. The goal is to demonstrate practical skills in threat detection, response, and process improvement through real-world examples.

## About

As a passionate cybersecurity professional with a background in SOC analysis and business process automation, I've worked on various initiatives to enhance security posture and operational efficiency. This repository highlights specific instances of:

* **SIEM Rule Tuning:** Examples of how detection rules in platforms like Azure Sentinel and Sumo Logic were refined to reduce false positives and improve accuracy.
* **Security Automation:** Scripts and approaches used to automate routine security tasks, threat intelligence analysis, and incident response steps.
* **Security Projects:** Overviews or examples from larger security-related projects, such as the creation of analytical workbooks or development of automation tools.

## Contents

You will find examples related to:

* **Sumo Logic Rule Tuning:** Specific examples of Sumo Logic queries and the logic changes implemented for tuning.
* **Azure Sentinel Rule Tuning:** Examples of KQL queries and tuning methodologies for Sentinel detection rules.
* **Automation Scripts:** (Future additions) Python or other scripts developed for tasks like IOC extraction or data analysis.
* **Workbook/Dashboard Examples:** (Future additions) Concepts or snippets related to creating analytical workbooks (e.g., Azure Sentinel Workbooks).

## Examples

* **Sumo Logic: "vCenter - Invalid Login Attempt" Tuning:** See the updated logic to correctly prioritize OR statements and accurately match VMware ESX authentication failures.
* **Sentinel: "Threat Essentials - Time series anomaly for data size transferred to public internet" Tuning:** Learn how correlating Destination IPs with threat intelligence feeds helped reduce false positives from benign traffic from known service providers.
* **Sentinel: "Process Execution Frequency Anomaly" Tuning:** Understand the approach to increasing granularity in baseline calculations for more precise anomaly detection.
* **Sumo Logic: "Local User Created" Tuning:** Review the logic added to ignore Event ID 4720 when it originates from known domain controllers.

*(Note: Specific code snippets and detailed explanations for each example will be added in dedicated files or folders within the repository.)*

## Usage

This repository is intended as a reference for:

* Security analysts looking for practical examples of SIEM rule tuning.
* Professionals interested in security automation techniques.
* Anyone wanting to see real-world applications of security concepts.

Feel free to explore the examples, adapt the logic to your own environment (with necessary modifications for your specific SIEM platform and data sources), and learn from the approaches presented.

## Contact

If you have any questions or would like to discuss the content of this repository, feel free to connect with me via:

* **LinkedIn:** [www.linkedin.com/in/malak-y-704a65137]

---

*This README is a living document and will be updated as more content and examples are added to the repository.*
