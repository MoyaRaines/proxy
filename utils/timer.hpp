#pragma once
#ifndef TIMER_H
#define TIMER_H

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

class Timer final : public std::enable_shared_from_this<Timer> {
public:
    static std::shared_ptr<Timer> Create(boost::asio::io_context* context) {
        return std::shared_ptr<Timer>(new Timer(context));
    }

    ~Timer() {
        delete m_timer;
        spdlog::trace("Timer destroy success.");
    };


    void asyncWait(int seconds, std::function<void(const boost::system::error_code&)> callback) {
        m_timer->expires_from_now(boost::posix_time::seconds(seconds));
        auto weak_self = weak_from_this();
        auto wrappedCallback = [weak_self, callback](const boost::system::error_code& ec) {
            if (auto self = weak_self.lock()){
                callback(ec);
            }
        };
        m_timer->async_wait(wrappedCallback);
    }

    void cancelAsyncEvent(){
        try {
            m_timer->cancel();
        } catch (const boost::system::system_error& e) {
        } catch (...) {
        }
    }

private:
    Timer(boost::asio::io_context* context) {
        m_timer = new boost::asio::deadline_timer(*context);
        spdlog::trace("Timer construct success.");
    }
    boost::asio::deadline_timer* m_timer;
};


#endif

