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
#include <functional>
#include <stdexcept>
#include <algorithm>
#include <list>
#include <iomanip>
#include <sstream>

#define PORT 3648

class Service;
class ClientSocketService;
class ServerSocketService;
class TimerConnectionService;
struct User;
bool authorize(const User & user);
bool is_number(const std::string& s);
std::string convert_char(unsigned char n);
std::string convert_int(size_t n);

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
    std::string name = "";
    size_t sum = 0;
    std::string password = "";
};

class Service {
};

class Buffer {
public:
    Buffer(int fd) : fd(fd) {
        vector.reserve(100);
        vector.resize(100);
    }

    unsigned char get() {
        if(point >= size){
            read();
        }
        char ret = vector.at(point++);
        return ret;
    }

private:
    std::vector<unsigned char> vector;
    int fd;
    int size = 0;
    int point = 0;
    void read () {
        size = recv(fd, vector.data(), 100, 0);
        point = 0;
        if(size == -1) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
//        vector.resize(err);
    }
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
        if (listen(server_fd, 100) < 0)
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
        buffer = new Buffer(newSocket);
    };

    void run() {
        this->setTimeout();
        this->authentificate();
        this->startSequence();
        timerConnectionService->stop();
        close(new_socket);
        shutdown(new_socket, 2);
    }

    void readLine(std::string * output, size_t * sum) {
        unsigned char ch = 0x00;
        int err = 1;
        char lastChar = 0x00;
        while (true) {
            ch = buffer->get();
            if (ch == '\n' && lastChar == '\r') {
                output->pop_back();
                * sum -= '\r';
                break;
            }
            output->push_back(ch);
            * sum += ch;
            lastChar = ch;
        };
        if(!shouldRun || err == -1) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
    }

    void readLine(std::string *output, bool shouldIgnore = false) {
        unsigned char ch = 0x00;
        int err = 1;
        char lastChar = 0x00;
        while (true) {
            ch = buffer->get();
            if (ch == '\n' && lastChar == '\r') {
                if (!shouldIgnore) {
                    output->pop_back();
                }
                break;
            }
            if (!shouldIgnore) {
                output->push_back(ch);
            }
            lastChar = ch;
        };
        if(!shouldRun || err == -1) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
    }

    void readWord(std::string *output) {
        unsigned char ch = 0x00;
        int err = 1;
        bool fail = false;
        while (true) {
            ch = buffer->get();
            if (ch == ' ') {
                break;
            }
            if (ch < '0' || ch > '9') {
                throw std::invalid_argument(getMessage(Message::_501));
            }
            *output += ch;
        };
        if (!shouldRun) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
    }

    void readLetters(std::string *output, int till, bool isMain = false) {
        unsigned char ch = 0x00;
        int err = 1;
        size_t counter = 0;
        while (true) {
            ch = buffer->get();
            counter++;
            *output += ch;
            if (counter >= till) {
                break;
            }
            if(counter == 1 && isMain && (ch != 'I' && ch != 'F')) {
                break;
            }
        };
        std::cout << "Read Letters:\t\t" << *output << std::endl;
        if(!shouldRun) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
    }

    void readLetters(size_t *output, int till) {
        unsigned char ch = 0x00;
        size_t counter = 0;
        while (true) {
            ch = buffer->get();
            counter++;
            *output += ch;
            if (counter >= till) {
                break;
            }
        };
        if(!shouldRun) {
            throw std::invalid_argument(getMessage(Message::_000));
        }
    }

    void sendMessage(Message message) {
        std::string temp = getMessage(message);
        if(!shouldRun) {
            return;
        }
        send(new_socket , temp.c_str() , temp.size() , 0 );
        std::cout << "SOCKET ID: " << new_socket << " " << "Send:\t\t" << temp;
    }

    void sendData(std::string temp) {
        if(!shouldRun) {
            return;
        }
        send(new_socket , temp.c_str() , temp.size() , 0 );
        std::cout << "SOCKET ID: " << new_socket << " " << "Send:\t" << temp << std::endl;
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
        this->readLine(&user.name, &user.sum);
        this->sendMessage(Message::_201);
        this->readLine(&user.password);
        std::cout << "SOCKET ID: " << new_socket << " " << "Password:\t" << user.password << std::endl;
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
        std::string checkSum;
        while(shouldRun) {
            std::string temp = "";
            type = "";
            this->readLetters(&type, 5, true);
            if(type == "INFO ") {
                type.clear();
                this->readLine(&temp, true);
                this->sendMessage(Message::_202);
                continue;
            }
            if(type == "FOTO ") {

                // Get size
                temp = "";
                this->readWord(&temp);
                size = atoi(temp.c_str());


                // Read bytes
                sum = 0;
                this->readLetters(&sum, size);
                std::string res = convert_int(sum);

                // Read checksum
                checkSum = "";
                checkSum += convert_char(buffer->get());
                checkSum += convert_char(buffer->get());
                checkSum += convert_char(buffer->get());
                checkSum += convert_char(buffer->get());
                if(res == checkSum) {
                    this->sendMessage(Message::_202);
                } else {
                    this->sendMessage(Message::_300);
                }
                continue;
            }
            timerConnectionService->stop();
            this->sendMessage(Message::_501);
            shutdown(this->new_socket, 2);
            break;
        }
    }
    User user;
    int new_socket = 0;
    TimerConnectionService* timerConnectionService;
    Buffer * buffer;
};

std::string convert_char(unsigned char n)
{
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << int(n);
    return ss.str();
}

std::string convert_int(size_t n)
{
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << n;
    return ss.str();
}

bool authorize(const User & user) {
    auto temp = user.name.substr(0, 5);
    if(temp != "Robot") {
        return false;
    }
    // check password
    unsigned long long sum = 0;
    for (char i : user.name) {
        sum += (int)i;
    }
    return std::to_string(user.sum) == user.password;
}

void clientConnectedTask (int socket) {
     ClientSocketService clientSocketService(socket);
    try {
        clientSocketService.run();
    } catch (const std::invalid_argument& e) {
        std::cout << e.what();
        clientSocketService.sendData(e.what());
        close(socket);
        shutdown(socket, 2);
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