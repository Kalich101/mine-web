const axios = require("axios");
const readline = require("readline");
const tough = require("tough-cookie");
const { wrapper } = require("axios-cookiejar-support");

// 🔹 Создаем cookie-хранилище
const cookieJar = new tough.CookieJar();
const apiClient = wrapper(axios.create({ jar: cookieJar, withCredentials: true }));

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function askQuestion(query) {
  return new Promise((resolve) => rl.question(query, resolve));
}

// 🔹 Функция для генерации случайных данных (рандомное устройство)
function generateRandomDeviceProfile() {
  const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
  ];
  const platforms = ["Win32", "MacIntel", "Linux x86_64"];
  const timezones = Array.from({ length: 24 }, (_, i) => (i - 12) * 60);
  const screenSizes = [{ width: 1366, height: 768 }, { width: 1920, height: 1080 }, { width: 1440, height: 900 }];

  return {
    identifier: `${Math.floor(Math.random() * 9999999999)}-${Math.floor(Math.random() * 9999999999)}-${Math.floor(Math.random() * 9999999999)}`,
    metadata: {
      hardware: {
        deviceMemory: [2, 4, 8, 16][Math.floor(Math.random() * 4)],
        hardwareConcurrency: [2, 4, 6, 8, 12][Math.floor(Math.random() * 5)],
        display: screenSizes[Math.floor(Math.random() * screenSizes.length)]
      },
      browser: { userAgent: userAgents[Math.floor(Math.random() * userAgents.length)] },
      platform: { platform: platforms[Math.floor(Math.random() * platforms.length)], timezone: timezones[Math.floor(Math.random() * timezones.length)] }
    }
  };
}

async function checkLogin(email, password) {
  try {
    // 🔹 Первый запрос: Получаем `authId`
    let response = await apiClient.post(
      "https://api.olb.postbank.de/oneid/am/json/realms/root/realms/consumer/authenticate?ForceAuth=true&authIndexType=service&authIndexValue=onlineBanking",
      {}
    );
    console.log("\n\033[34mОтвет от API (Шаг 1, получение authId):\033[0m");
    console.log(JSON.stringify(response.data, null, 2));

    if (response.data.authId) {
      let authId = response.data.authId;
      let randomProfile = generateRandomDeviceProfile();

      // 🔹 Второй запрос: Ввод логина + данные устройства
      let loginPayload = {
        authId: authId,
        callbacks: [
          { type: "NameCallback", output: [{ name: "prompt", value: "OneId" }], input: [{ name: "IDToken1", value: email }], _id: 0 },
          { type: "DeviceProfileCallback", output: [{ name: "metadata", value: true }], input: [{ name: "IDToken2", value: JSON.stringify(randomProfile) }], _id: 1 }
        ]
      };
      console.log("\n📤 Отправляем payload (Шаг 2, ввод логина):");
      console.log(JSON.stringify(loginPayload, null, 2));

      response = await apiClient.post(
        "https://api.olb.postbank.de/oneid/am/json/realms/root/realms/consumer/authenticate?ForceAuth=true&authIndexType=service&authIndexValue=onlineBanking",
        loginPayload
      );
      console.log("\n\033[34mОтвет от API (Шаг 2, логин отправлен):\033[0m");
      console.log(JSON.stringify(response.data, null, 2));



      // 🔹 Третий запрос: Ввод пароля
      if (response.data.stage === "password") {
        authId = response.data.authId;
        let passwordPayload = {
          authId: authId,
          callbacks: [
            { type: "PasswordCallback", output: [{ name: "prompt", value: "Password" }], input: [{ name: "IDToken1", value: password }], _id: 2 },
            { type: "MetadataCallback", output: [{ name: "data", value: { oneId: email } }], _id: 3 },
            {
              type: "ConfirmationCallback",
              output: [
                { name: "prompt", value: "" },
                { name: "messageType", value: 0 },
                { name: "options", value: ["next", "back"] },
                { name: "optionType", value: -1 },
                { name: "defaultOption", value: 0 }
              ],
              input: [{ name: "IDToken3", value: 0 }],
              _id: 4
            }
          ]
        };

        console.log("\n📤 Отправляем payload (Шаг 3, ввод пароля):");
        console.log(JSON.stringify(passwordPayload, null, 2));

        response = await apiClient.post(
          "https://api.olb.postbank.de/oneid/am/json/realms/root/realms/consumer/authenticate?ForceAuth=true&authIndexType=service&authIndexValue=onlineBanking",
          passwordPayload
        );

        console.log("\n\033[34mОтвет от API (Шаг 3, пароль отправлен):\033[0m");
        console.log(JSON.stringify(response.data, null, 2));

        if (response.data.stage === "success") {
          console.log("\033[32m✅ Успешный вход!\033[0m");
        } else {
          console.log("\033[31m❌ Неверный логин или пароль.\033[0m");
        }
      } else {
        console.log("\033[31m❌ Ошибка: API не запросило пароль.\033[0m");
      }
    } else {
      console.log("\033[31m❌ Ошибка: Не получен authId.\033[0m");
    }
  } catch (error) {
    console.error("\033[31m%s\033[0m", "Ошибка при запросе к API:", error.message);
  }
}

(async () => {
  let email = await askQuestion("Введите логин: ");
  let password = await askQuestion("Введите пароль: ");
  rl.close();
  await checkLogin(email, password);
})();
