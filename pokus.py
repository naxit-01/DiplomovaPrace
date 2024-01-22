import asyncio

async def my_coroutine(text):
    print(f"Starting the coroutine {text}")
    await asyncio.sleep(3)
    print(f"Coroutine finished {text}")
    return 42

async def main():
    tasks = []

    tasks.append(asyncio.create_task(my_coroutine("text1")))
    tasks.append(asyncio.create_task(my_coroutine("text2")))
    
    await asyncio.sleep(1)

    # Zrušení všech úloh a odstranění z listu
    tasks_to_remove = []
    for task in tasks:
        task.cancel()
        tasks_to_remove.append(task)
    await asyncio.sleep(0)
    tasks.append(asyncio.create_task(my_coroutine("text3")))

    for task in tasks_to_remove:
        tasks.remove(task)

    await asyncio.sleep(5)

    # Vytvoření a spuštění nové úlohy
    tasks.append(asyncio.create_task(my_coroutine("text3")))
    
    await asyncio.sleep(5)

# Spuštění běžící smyčky pomocí asyncio.run()
asyncio.run(main())
