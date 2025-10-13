# JWT/OAuth Attack & Defense Lab (Flask)

Demo các lỗi phổ biến về JWT:
- **RS/HS confusion** (xác minh bằng HS với public key)
- **`kid` injection/path traversal** để chọn key tuỳ ý
- (tuỳ chọn) **alg: none** nếu bật sai
Kèm bản vá: enforce `alg/iss/aud`, JWKS, key rotation đơn giản.

## Chạy nhanh
```bash
python3 -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app_vulnerable.py         # bản dễ bị tấn công
# hoặc
python app_hardened.py           # bản đã vá
```
Truy cập: `http://127.0.0.1:5000`

## Routes
- `POST /login` → trả JWT (user demo: alice/alice)
- `GET /profile` → cần Bearer token
- `GET /jwks.json` → JWKS (bản hardened dùng)

## Tấn công RS/HS confusion (tóm tắt)
1) Lấy **public key** (PEM) của server (bản vulnerable để lộ).
2) Tạo JWT với `alg=HS256` nhưng dùng **public key** như secret để ký.
3) Gửi token → server (vulnerable) chấp nhận.

## Tấn công kid injection
1) Tạo header JWT có `"kid": "../../keys/public.pem"` hoặc `"kid":"custom"`.
2) Server vulnerable load file theo `kid` không kiểm soát → dùng nội dung file làm secret.

## Phòng thủ
- Fix thuật toán: chỉ chấp nhận **RS256** (hoặc thu hẹp tập thuật toán).
- Xác thực **iss/aud/exp** nghiêm ngặt.
- JWKS: tra cứu key qua `kid` từ **danh sách tin cậy**, không đọc file tuỳ ý.
- Không bao giờ dùng public key làm secret HMAC.
