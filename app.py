from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import pyotp
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from dotenv import load_dotenv  # python-dotenv 임포트
import os  # os 모듈 임포트

# 환경 변수 로드
load_dotenv(os.path.join(os.path.dirname(__file__), 'adress.env'))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CORS 설정
CORS(app)

# 모델 임포트 및 SQLAlchemy 초기화
from models import db, User
db.init_app(app)

# 이메일 설정 (환경 변수에서 가져옴)
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

# 이메일 설정 값 확인 (디버깅용, 선택 사항)
if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
    raise ValueError("EMAIL_ADDRESS 또는 EMAIL_PASSWORD가 설정되지 않았습니다. .env 파일을 확인하세요.")

def send_email(to_email, otp):
    msg = MIMEText(f"귀하의 OTP는 {otp}입니다. 60초 내에 입력해주세요.")
    msg['Subject'] = '블로그 인증 OTP'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())

# 회원가입 엔드포인트
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': '이메일과 비밀번호를 입력해주세요.'}), 400

    # 이메일 중복 확인
    if User.query.filter_by(email=email).first():
        return jsonify({'error': '이미 등록된 이메일입니다.'}), 400

    # 비밀번호 해싱
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # OTP 비밀 키 생성
    otp_secret = pyotp.random_base32()

    # 사용자 생성
    user = User(email=email, password_hash=password_hash, otp_secret=otp_secret)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': '회원가입 성공!'}), 201

# 로그인 엔드포인트
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': '존재하지 않는 이메일입니다.'}), 404

    # 비밀번호 검증
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'error': '잘못된 비밀번호입니다.'}), 401

    # OTP 생성
    totp = pyotp.TOTP(user.otp_secret, interval=30)  # 30초 주기
    otp = totp.now()

    # OTP 이메일 전송
    try:
        send_email(user.email, otp)
    except Exception as e:
        return jsonify({'error': 'OTP 전송 실패: ' + str(e)}), 500

    return jsonify({'message': 'OTP가 이메일로 전송되었습니다.', 'user_id': user.id}), 200

# OTP 검증 엔드포인트
@app.route('/otp/verify', methods=['POST'])
def verify_otp():
    data = request.get_json()
    user_id = data.get('user_id')
    otp = data.get('otp')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '사용자를 찾을 수 없습니다.'}), 404

    # OTP 검증
    totp = pyotp.TOTP(user.otp_secret, interval=30)
    if not totp.verify(otp, valid_window=2):  # 60초 유효 시간 (30초 주기 * 2)
        return jsonify({'error': '만료된 OTP 또는 잘못된 OTP입니다.'}), 401

    return jsonify({'message': '인증 성공!'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 데이터베이스 테이블 생성
    app.run(debug=True, port=5000)