import sqlite3
import json
import os

##### truffleparse.py #####
# Parses a folder of Trufflehog JSON files into a database for analysis

# Set the path to your SQLite3 database file
database_path = "truffle.sqlite3"
# Set the directory containing Trufflehog JSON output files
directory_path = "./"

###########################

### Reference Queries ###
# SELECT DISTINCT detectorname FROM truffle;
# SELECT DISTINCT raw FROM truffle ORDER BY raw ASC;
# SELECT raw FROM truffle where raw like '%test.org%';
# SELECT DISTINCT raw,repo,file FROM truffle WHERE detectorname = 'AWS';
# SELECT raw, GROUP_CONCAT(repo) as repos FROM truffle GROUP BY raw;




# Connect to the SQLite3 database
conn = sqlite3.connect(database_path)
c = conn.cursor()

# Create the table to hold the Trufflehog results
c.execute('''CREATE TABLE IF NOT EXISTS truffle
            (
                repo TEXT,
                branch TEXT,
                file TEXT,
                line int,
                raw TEXT,
                detectorname TEXT,
                extradata TEXT
            )
''')

for filename in os.listdir(directory_path):
    if not filename.endswith(".json"):
        continue
    file_path = os.path.join(directory_path, filename)
    if os.path.isfile(file_path):
        # Do something with the file
        print(f"Found file: {file_path}")
        # Load the Trufflehog JSON output file
        with open(file_path, "r") as f:
            for finding in f.readlines():
                print(finding)
                result = json.loads(finding)

                # Insert the Trufflehog results into the database
                repo = result["SourceMetadata"]["Data"]["Git"].get("repository")
                branch = result["SourceMetadata"]["Data"]["Git"].get("commit")
                file = result["SourceMetadata"]["Data"]["Git"].get("file")
                line = result["SourceMetadata"]["Data"]["Git"].get("line")
                raw = result.get("Raw")
                detectorname = result.get("DetectorName")
                extradata = str(result.get("ExtraData"))
                c.execute("INSERT INTO truffle (repo, branch, file, line, raw, detectorname, extradata) VALUES (?, ?, ?, ?, ?, ?, ?)", (repo, branch, file, line, raw, detectorname, extradata))

            # Commit the changes and close the database connection
            conn.commit()
    else:
        # Handle directories or other non-file objects
        print(f"Found directory: {file_path}")


conn.close()

print("Trufflehog results ingested into the database successfully.")