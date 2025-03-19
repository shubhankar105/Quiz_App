from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import datetime
import json

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    questions = db.Column(db.Text, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('quizzes', lazy=True))



with app.app_context():
    db.create_all()



@app.route('/')
def home():
    return redirect(url_for('login_page'))


@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/register')
def register_page():
    return render_template('register.html')


@app.route('/create_quiz')
def create_quiz_page():
    return render_template('create_quiz.html')


@app.route('/viewquiz/<int:quiz_id>')
def view_quiz_page(quiz_id):
    return render_template('view_quiz.html', quiz_id=quiz_id)



@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': 'Username and password required.'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Username already exists.'}), 400

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        access_token = create_access_token(identity=str(new_user.id), expires_delta=datetime.timedelta(hours=1))

        return jsonify({'message': 'User registered successfully.', 'access_token': access_token}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            return jsonify({'message': 'Invalid credentials.'}), 401

        access_token = create_access_token(identity=str(user.id), expires_delta=datetime.timedelta(hours=1))

        return jsonify({'access_token': access_token}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500



@app.route('/quiz', methods=['POST'])
@jwt_required()
def create_quiz():

    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        title = data.get('title')
        questions = data.get('questions')

        if not title or not isinstance(questions, list) or len(questions) == 0:
            return jsonify({'message': 'Invalid quiz data.'}), 400


        for q in questions:
            if "correctAnswer" not in q:
                return jsonify({'message': 'Each question must have a correctAnswer field.'}), 400


            correct_index = q["correctAnswer"] - 1

            if isinstance(correct_index, int):
                if 0 <= correct_index < len(q["options"]):
                    q["correctAnswer"] = q["options"][correct_index]
                else:
                    return jsonify({'message': f'Invalid correctAnswer index for question: {q["questionText"]}'}), 400

        questions_str = json.dumps(questions)
        new_quiz = Quiz(title=title, questions=questions_str, user_id=current_user_id)
        db.session.add(new_quiz)
        db.session.commit()

        return jsonify({'message': 'Quiz created successfully.', 'quiz_id': new_quiz.id}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/quiz/<int:quiz_id>', methods=['GET'])
@jwt_required()
def get_quiz(quiz_id):
    try:
        current_user_id = get_jwt_identity()
        quiz = Quiz.query.filter_by(id=quiz_id, user_id=current_user_id).first()

        if not quiz:
            return jsonify({'message': 'Quiz not found or unauthorized.'}), 404

        questions = json.loads(quiz.questions)

        for q in questions:
            q.pop('correctAnswer', None)

        return jsonify({'id': quiz.id, 'title': quiz.title, 'questions': questions}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/quiz/<int:quiz_id>/answer', methods=['POST'])
@jwt_required()
def check_answer(quiz_id):

    try:
        current_user_id = get_jwt_identity()
        quiz = Quiz.query.filter_by(id=quiz_id, user_id=current_user_id).first()

        if not quiz:
            return jsonify({'message': 'Quiz not found or unauthorized.'}), 404

        data = request.get_json()
        question_text = data.get("question")
        selected_answer = str(data.get("selected_answer")).strip()

        if not question_text or not selected_answer:
            return jsonify({'message': 'Invalid request. Question and answer required.'}), 400

        questions = json.loads(quiz.questions)

        for q in questions:
            if str(q.get("questionText")).strip() == question_text.strip():
                correct_answer = str(q.get("correctAnswer")).strip()

                print(f"DEBUG -> Selected: '{selected_answer}', Correct: '{correct_answer}'")

                if selected_answer.lower() == correct_answer.lower():
                    return jsonify({"correct": True, "correct_answer": correct_answer}), 200
                else:
                    return jsonify({"correct": False, "correct_answer": correct_answer}), 200

        return jsonify({'message': 'Question not found in quiz.', "correct": False}), 404

    except Exception as e:
        return jsonify({'message': str(e), "correct": False}), 500
if __name__ == '__main__':
    app.run(debug=True)