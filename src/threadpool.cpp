#include "threadpool.hpp"

namespace utils
{
    void ThreadPool::submit( Request req )
    {
        boost::unique_lock<boost::mutex> lock( mMutex );
        mRequests.push_back( req );
        mCondition.notify_all();
    }

    Request ThreadPool::pop()
    {
        boost::unique_lock<boost::mutex> lock( mMutex );
        while ( mRequests.empty() )
            mCondition.wait( lock );

        Request req = mRequests[0];
        mRequests.pop_front();

        mCondition.notify_all();
        return req;
    }

    void ThreadPool::work()
    {
        while ( mIsContinue ) {
            Request req = pop();
            req();
        }
    }

    void ThreadPool::start()
    {
        for ( unsigned int i = 0 ; i < mThreadCount ; i++ )
            mThreads.push_back( std::make_shared<boost::thread>( &ThreadPool::work, this ) );
    }

    void ThreadPool::join()
    {
        for ( auto th : mThreads )
            th->join();
    }

    void ThreadPool::stop()
    {
        mIsContinue = false;
    }
}
