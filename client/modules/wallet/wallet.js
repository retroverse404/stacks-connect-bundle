const appConfig = new stacksConnect.AppConfig(['store_write','publish_data']);
const userSession = new stacksConnect.UserSession({ appConfig });
const appDetails = { name: "Finding Nakamoto", icon: "https://placehold.co/64" };

document.getElementById("btn-connect").onclick = () => {
  stacksConnect.showConnect({
    appDetails, userSession,
    onFinish: () => {
      const data = userSession.loadUserData();
      const addr = data?.profile?.stxAddress?.testnet;
      document.getElementById("addr").textContent = addr || "Connected";
    }
  });
};
