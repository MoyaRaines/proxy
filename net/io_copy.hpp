#ifndef _IO_COPY_HPP
#define _IO_COPY_HPP

#include <chrono>
#include <ctime>

#include <spdlog/spdlog.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include "../net/tcp_session.hpp"

class IOCopy{
public:
	virtual ~IOCopy(){
	}

    void startIOCopy(std::shared_ptr<TcpSession> session_a, std::shared_ptr<TcpSession> session_b, size_t buffer_size){
        m_buffer.resize(buffer_size, '\0');
        m_bytes_transferred = 0;
        m_start_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

        m_sessionA = session_a;
        m_sessionB = session_b;

        transferData(true);
        transferData(false);
    }

    void transferData(bool positiveSequence){
        auto source = positiveSequence ? m_sessionA : m_sessionB;
        source->asyncReadSomeData(m_buffer.data(), m_buffer.size(), [this, positiveSequence](const boost::system::error_code& ec, std::size_t bytes_transferred){
            if(!ec){
                // spdlog::trace("Read data from {} {} bytes.", session_1->getRemoteAddress(), bytes_transferred);
                m_bytes_transferred += bytes_transferred;

                auto destination = positiveSequence ? m_sessionB : m_sessionA;
                destination->asyncWriteData(m_buffer.data(), bytes_transferred, [this, positiveSequence](const boost::system::error_code& ec, std::size_t bytes_transferred){
                    if(!ec){
                        // spdlog::trace("Write data to {} {} bytes.", session_2->getRemoteAddress(), bytes_transferred);
                        this->transferData(positiveSequence);
                    }else{
                        // spdlog::trace("Write data to {} failed, error: {}", session_2->getRemoteAddress(), ec.message());
                        m_end_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                        this->IOCopyEnd();
                    }
                });
            }else{
                // spdlog::trace("Read data from {} failed, error: {}", session_1->getRemoteAddress(), ec.message());
                m_end_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                this->IOCopyEnd();
            }
        });
    }

    void IOCopyEnd(){
        m_sessionA.reset();
        m_sessionB.reset();
        this->onIOCopyFinished();
    }

    virtual void onIOCopyFinished() = 0;    
    
    std::vector<char> m_buffer;
    size_t m_bytes_transferred;

    std::time_t m_start_time;
    std::time_t m_end_time;

    std::shared_ptr<TcpSession> m_sessionA;
    std::shared_ptr<TcpSession> m_sessionB;
};
#endif