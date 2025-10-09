# Cybersecurity Radar

Proof of concept : check proof_of_concept_CASI_api.py. It contains a python script that makes a basic radar based on real data.

Uses :
- React (projected)
- Django
- Postgres

Data plan :
- enumerated types :
  - category (radar quadrant)
  - interest
  - (potentially) short, medium or long term
- radar blip :
  - title
  - category
  - short, medium or long term OR numerical value representing the position on the radar, so preprocessed
  - qualitative qualifier (importance)
  - description
  - source/link
  - interests (list)
  - added date
  - expiration date
- utilisateur :
  - username
  - password hash
  - interests (list)

## Apps :

- renderer : the svg renderer. It queries from the database the data pertaining to the user and places blips on the radar according to the data, then answers with the svg file.
- populate : gets data from our determined API and sources, and formats and inserts it in the database. Runs regularly, on a cron job.

## Running

Install dependancies in a venv :
```bash
python -m venv
. venv/bin/activate
pip install -r requirements.txt
```
