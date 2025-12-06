# test_ai.py
import ai_manager # 우리가 만든 모듈

print("Running AI Test...")
try:
    # 테스트 요청
    response = ai_manager.ask_ai("테스트 항목", "테스트 설명", "PermitRootLogin yes")
    print("\n✅ 성공! AI 응답:")
    print(response)
except Exception as e:
    print(f"\n❌ 실패! 에러 내용:\n{e}")
