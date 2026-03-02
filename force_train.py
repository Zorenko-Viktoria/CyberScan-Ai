import asyncio
from ai_auto_trainer import ai_trainer

async def force_train():
    print("🚀 Принудительное обучение...")
    result = await ai_trainer.auto_train(force=True)
    
    if result:
        print(f"✅ Успех! Точность: {result['accuracy']:.3f}")
        print(f"   Precision: {result['precision']:.3f}")
        print(f"   Recall: {result['recall']:.3f}")
        print(f"   F1: {result['f1']:.3f}")
    else:
        print("❌ Недостаточно данных для обучения")

if __name__ == "__main__":
    asyncio.run(force_train())