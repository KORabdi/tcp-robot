/**
 * @author Konstantin Kozokar - Student of CTU
 */
#include <iostream>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <cstring>
#include <functional>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <list>

#define PORT 3648

class Service;
class ClientSocketService;
class ServerSocketService;
class TimerConnectionService;
struct User;
bool authorize(const User & user);
bool is_number(const std::string& s);

std::map<std::string, Service*> serviceProvider;

enum Message {_200, _201, _202, _300, _500, _501, _502, _000};
std::string getMessage(Message message) {
    switch (message){
        case _200:
            return "200 LOGIN\r\n";
        case _201:
            return "201 PASSWORD\r\n";
        case _202:
            return "202 OK\r\n";
        case _300:
            return "300 BAD CHECKSUM\r\n";
        case _500:
            return "500 LOGIN FAILED\r\n";
        case _501:
            return "501 SYNTAX ERROR\r\n";
        case _502:
            return "502 TIMEOUT\r\n";
        case _000:
            return "NULL";
    }
}
struct User {
    std::string name = std::string(10000000, 0x00);
    std::string password = std::string(100000, 0x00);
};

class Service {
};

class TimerConnectionService : public Service {
public:
    void run (ClientSocketService* service, const std::function<void(ClientSocketService*)>& callback, int time = 45) {
        std::thread* t1 = new std::thread([=] {
            std::this_thread::sleep_for(std::chrono::seconds(time));
            if(this->shouldRun) {
                callback(service);
            }
        });
    }

    void stop() {
        shouldRun = false;
    }

private:
    bool shouldRun = true;
};

class ServerSocketService : public Service {
    public:
    ServerSocketService(){
        createFileDescriptor();
        attachPort();
        setAddress();
        bindPort();
        listenPort();
    }

    int acceptSocket() {
        int new_socket = 0;
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                                 (socklen_t*)&addrlen))<0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        return new_socket;
    }

    bool shouldAppRun() {
        return this->runApp;
    }

    void closeSocket() {
        close(server_fd);
    }

    ServerSocketService& operator= (const Service& x) {return *this;}

private:
    int server_fd{};
    struct sockaddr_in address{};
    int opt = 1;
    int addrlen = sizeof(address);
    int runApp = true;

    void createFileDescriptor() {
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }
    }

    void attachPort() {
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,&opt, sizeof(opt)))
        {
            perror("setsockopt");
            exit(EXIT_FAILURE);
        }
    }

    void setAddress() {
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons( PORT );
    }

    void bindPort() {
        if (bind(server_fd, (struct sockaddr *)&address,
                 sizeof(address))<0)
        {
            perror("bind failed");
            exit(EXIT_FAILURE);
        }
    }

    void listenPort() {
        if (listen(server_fd, 20) < 0)
        {
            perror("listen");
            exit(EXIT_FAILURE);
        }
    }
};

class ClientSocketService : public Service {
    public:
    bool shouldRun = true;
    explicit ClientSocketService(int newSocket) {
        new_socket = newSocket;
        timerConnectionService = (TimerConnectionService*)serviceProvider["TimerConnectionService"];
    };

    void run() {
        this->setTimeout();
        this->authentificate();
        this->startSequence();
        timerConnectionService->stop();
        close(new_socket);
    }

    void readLine(std::string *output, bool shouldIgnore = false) {
        char ch = 0x00;
        int err = 1;
        char lastChar = 0x00;
        size_t counter = 0;
        while ((err = recv(new_socket, &ch, 1, 0)) != -1) {
            if (ch == '\n' && lastChar == '\r') {
                counter--;
                break;
            }
            if (!shouldIgnore) {
                char* temp = &output->at(counter++);
                *temp = ch;
            }
            lastChar = ch;
        };
        *output = output->substr(0, counter);
        if(!shouldRun || err == -1) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
    }

    void readWord(std::string *output) {
        char ch = 0x00;
        int err = 1;
        while ((err = recv(new_socket, &ch, 1, 0)) != -1) {
            if (ch == ' ') {
                break;
            }
            *output += ch;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        };
        if (!shouldRun || err == -1) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
        std::cout << "Receive:\t" << *output<< std::endl;
    }
    void readLetters(std::string *output, int till) {
        char ch = 0x00;
        int err = 1;
        size_t counter = 0;
        while ((err = recv(new_socket, &ch, 1, 0)) != -1) {
            counter++;
            *output += ch;
            if (counter >= till) {
                break;
            }
            if(counter == 1 && (ch != 'I' && ch != 'F')) {
                break;
            }
        };
        if(!shouldRun || err == -1) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
        std::cout << "Receive:\t" << *output << std::endl;
    }

    void sendMessage(Message message) {
        std::string temp = getMessage(message);
        if(!shouldRun) {
            return;
        }
        send(new_socket , temp.c_str() , temp.size() , 0 );
        std::cout << "Send:\t\t" << temp;
    }

    void sendData(std::string temp) {
        if(!shouldRun) {
            return;
        }
        send(new_socket , temp.c_str() , temp.size() , 0 );
        std::cout << "Send:\t" << temp << std::endl;
    }

    private:
    void setTimeout() {
        timerConnectionService->run(this, [](ClientSocketService* service){
            service->sendMessage(Message::_502);
            service->shouldRun = false;
            shutdown(service->new_socket, 2);
        });
    }
    void authentificate() {
        this->sendMessage(Message::_200);
        this->readLine(&user.name);
        this->sendMessage(Message::_201);
        this->readLine(&user.password);
        if(!authorize(user)) {
            timerConnectionService->stop();
            throw std::invalid_argument(getMessage(Message::_500));
        }
        this->sendMessage(Message::_202);
    }
    void startSequence() {
        size_t size = 0;
        std::string type;
        size_t sum = 0;
        int checkSum = 0;
        while(shouldRun) {
            std::string temp = "";
            this->readLetters(&type, 5);
            if(type == "INFO ") {
                type.clear();
                this->readLine(&temp, true);
                this->sendMessage(Message::_202);
                continue;
            }
            if(type == "FOTO ") {

                this->sendMessage(Message::_501);
                close(new_socket);

//                this->sendMessage(Message::_202);
//
//                // Get size
//                temp = "";
//                this->readWord(&temp);
//                if(!is_number(temp))
//                    throw std::invalid_argument(getMessage(Message::_502));
//                size = atoi(temp.c_str());
//
//                // Read bytes
//                temp = "";
//                sum = 0;
//                this->countLetters(&sum, size);
//
//                // Read checksum
//                temp = "";
//                this->readLetters(&temp, 4);
//                checkSum = temp[0] * 1000000 + temp[1] * 10000 + temp[2] * 100 + temp[3];
//
//                if(checkSum == sum) {
//                    this->sendMessage(Message::_202);
//                } else {
//                    this->sendMessage(Message::_300);
//                }
//                continue;
            }
            timerConnectionService->stop();
            throw std::invalid_argument(getMessage(Message::_501));
        }
    }
    User user;
    int new_socket = 0;
    TimerConnectionService* timerConnectionService;
};

bool authorize(const User & user) {
    auto temp = user.name.substr(0, 5);
    std::cout << "AUTHORIZING: \t" << temp.data() << std::endl << std::endl;
    if(temp != "Robot") {
        return false;
    }
    // check password
    size_t sum = 0;
    for (char i : user.name) {
        sum += i;
    }
    return std::to_string(sum) == user.password;
}

void clientConnectedTask (int socket) {
     ClientSocketService clientSocketService(socket);
    try {
        clientSocketService.run();
    } catch (const std::invalid_argument& e) {
        std::cout << e.what();
        clientSocketService.sendData(e.what());
        close(socket);
    }
}

bool is_number(const std::string& s)
{
    return !s.empty() && std::find_if(s.begin(),
                                      s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
}

void joinThreads(const std::vector<std::thread*>& threadList) {
    for (std::thread* th : threadList) {
        th->join();
    }
}

void deleteThreads(const std::vector<std::thread*>& threadList) {
    for (std::thread* th : threadList) {
        delete th;
    }
}

int main() {
    ServerSocketService serverSocketService;
    TimerConnectionService timerConnectionService;
    serviceProvider["ServerSocketService"] = &serverSocketService;
    serviceProvider["TimerConnectionService"] = &timerConnectionService;

    int socket;
    std::vector<std::thread*> threadList;
    std::thread* thread;
    while(serverSocketService.shouldAppRun()) {
        socket = serverSocketService.acceptSocket();
        thread = new std::thread(clientConnectedTask, socket);
        threadList.push_back(thread);
    }
    joinThreads(threadList);
    deleteThreads(threadList);
    serverSocketService.closeSocket();
    return 0;
}