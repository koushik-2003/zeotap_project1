from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import ast
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rules.db'
db = SQLAlchemy(app)

# Define your models here
class Node:
    def __init__(self, type, value=None, left=None, right=None):
        self.type = type  # "operator" or "operand"
        self.value = value  # For operands: the actual condition, for operators: AND/OR
        self.left = left  # Left child (another Node)
        self.right = right  # Right child (another Node)

    def __repr__(self):
        if self.type == "operand":
            return f"Operand({self.value})"
        return f"Operator({self.value}, left={self.left}, right={self.right})"

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_string = db.Column(db.String(500))
    ast_representation = db.Column(db.Text)

# Create rules from string
def create_rule(rule_string):
    try:
        tree = ast.parse(rule_string, mode='eval')
        return tree
    except SyntaxError:
        raise ValueError("Invalid rule syntax")

def ast_to_custom_ast(node):
    if isinstance(node, ast.BoolOp):
        op = "AND" if isinstance(node.op, ast.And) else "OR"
        left = ast_to_custom_ast(node.values[0])
        right = ast_to_custom_ast(node.values[1])
        return Node(type="operator", value=op, left=left, right=right)

    if isinstance(node, ast.Compare):
        condition = f"{node.left.id} {node.ops[0].__class__.__name__} {node.comparators[0].n}"
        return Node(type="operand", value=condition)

    return None

def evaluate_rule(data, node):
    if node.type == "operand":
        condition = node.value.split()
        attribute, operator, value = condition[0], condition[1], condition[2]
        attribute_value = data.get(attribute)

        if operator == "Gt":
            return attribute_value > int(value)
        elif operator == "Lt":
            return attribute_value < int(value)
        elif operator == "Eq":
            return attribute_value == value.strip("'")
        return False

    elif node.type == "operator":
        if node.value == "AND":
            return evaluate_rule(data, node.left) and evaluate_rule(data, node.right)
        elif node.value == "OR":
            return evaluate_rule(data, node.left) or evaluate_rule(data, node.right)

    return False

# Updated combine_rules function to avoid invalid syntax
def combine_rules(rule_strings):
    # Wrap each rule in parentheses to ensure valid expression
    combined_expression = " or ".join([f"({rule})" for rule in rule_strings])

    # Create the combined rule from this expression
    try:
        combined_ast = create_rule(combined_expression)
        # Convert it to the custom AST representation
        custom_ast = ast_to_custom_ast(combined_ast.body)
        return custom_ast
    except Exception as e:
        raise ValueError(f"Error combining rules: {str(e)}")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/create_rule', methods=['POST'])
def api_create_rule():
    rule_string = request.json['rule']
    try:
        rule_ast = create_rule(rule_string)
        custom_ast = ast_to_custom_ast(rule_ast.body)
        ast_json = json.dumps(custom_ast, default=lambda o: o.__dict__)

        new_rule = Rule(rule_string=rule_string, ast_representation=ast_json)
        db.session.add(new_rule)
        db.session.commit()

        return {"status": "Rule Created", "ast": ast_json}, 200
    except ValueError as e:
        return {"error": str(e)}, 400

@app.route('/combine_rules', methods=['POST'])
def api_combine_rules():
    rule_strings = request.json.get('rules', [])
    if not rule_strings:
        return {"error": "No rules provided"}, 400

    try:
        combined_ast = combine_rules(rule_strings)
        ast_json = json.dumps(combined_ast, default=lambda o: o.__dict__)
        return {"status": "Rules Combined", "ast": ast_json}, 200
    except Exception as e:
        return {"error": str(e)}, 400

@app.route('/evaluate_rule', methods=['POST'])
def api_evaluate_rule():
    json_data = request.json['data']
    rule_id = request.json['rule_id']

    rule = Rule.query.get(rule_id)
    ast_json = json.loads(rule.ast_representation, object_hook=lambda d: Node(**d))

    result = evaluate_rule(json_data, ast_json)
    return {"result": result}, 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the tables
    app.run(debug=True)
