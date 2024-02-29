# Create venv
python -m venv venv
# Enable venv
source venv/bin/activate
# Generate requirements.txt
pip freeze > requirements.txt
# Install packages from requirements.txt
pip install -r requirements.txt

# GraphiQL IDE
https://github.com/graphql/graphiql.git