#pragma once
#ifndef _ThreadPool_H_
#define _ThreadPool_H_

#include <iostream>  
#include <vector>  
#include <thread>  
#include <boost/asio.hpp>  
#include <spdlog/spdlog.h>


class IOContextThreadPool {
public:
    boost::asio::io_context* get_io_context() {
        if(m_poolSize == 0){
            return nullptr;
        }
        m_index++;
        if (m_index == m_poolSize)
            m_index = 0;
        return m_io_contexts[m_index];
    }

    static IOContextThreadPool* getInstance() {
        static IOContextThreadPool* m_instance;
        static std::once_flag onceFlag;
        std::call_once(onceFlag, []() {
            m_instance = new IOContextThreadPool();
        });
        return m_instance;
    }

private:
    std::vector<boost::asio::io_context*> m_io_contexts;
    std::vector<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> m_work_guards;

    std::vector<std::thread> m_threads;
    int m_index;
    size_t m_poolSize;


    IOContextThreadPool() {
        unsigned int num_cores = std::thread::hardware_concurrency();
        spdlog::info("Number of cpu cores: {}", num_cores);
        if (num_cores < 2) {
            num_cores = 2;
        }
        num_cores = num_cores * 1.5;

        m_index = 0;
        m_poolSize = num_cores;
        for (size_t i = 0; i < m_poolSize; ++i) {
            m_io_contexts.push_back(new boost::asio::io_context());
            m_work_guards.push_back(boost::asio::make_work_guard(*m_io_contexts[i]));
            m_threads.emplace_back([this, i] {
                (m_io_contexts[i])->run();
            });
        }

        spdlog::info("IO context thread pool construct success. Pool size: {}", m_poolSize);
    }

    IOContextThreadPool(const IOContextThreadPool&) = delete;
    IOContextThreadPool& operator=(const IOContextThreadPool&) = delete;
};
#endif