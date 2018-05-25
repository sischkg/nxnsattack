#ifndef THREAD_POOL_HPP
#define THREAD_POOL_HPP

#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <boost/function.hpp>
#include <deque>

namespace utils
{
    typedef boost::function<void ()> Request;

    class ThreadPool : private boost::noncopyable
    {
    public:
        ThreadPool( unsigned int thread_count )
            : mIsContinue( true ), mThreadCount( thread_count )
        {}

        void submit( Request req );
        void start();
        void join();
        void stop();
        void work();

    private:
        volatile bool mIsContinue;
        unsigned int  mThreadCount;
        std::deque<Request> mRequests;

        std::vector<std::shared_ptr<boost::thread>> mThreads;
        boost::mutex mMutex;
        boost::condition_variable mCondition;

        Request pop();
    };
}

#endif

