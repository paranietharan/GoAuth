package worker

import (
	"context"
	"log"

	"GoAuth/internal/notification/email"
)

type JobQueue struct {
	jobs chan email.EmailJob
}

func NewJobQueue(capacity int) *JobQueue {
	return &JobQueue{
		jobs: make(chan email.EmailJob, capacity),
	}
}

func (q *JobQueue) Push(job email.EmailJob) {
	q.jobs <- job
}

type EmailWorker struct {
	provider email.Provider
	jobQueue *JobQueue
}

func NewEmailWorker(provider email.Provider, jobQueue *JobQueue) *EmailWorker {
	return &EmailWorker{
		provider: provider,
		jobQueue: jobQueue,
	}
}

func (w *EmailWorker) Start(ctx context.Context, numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		go w.worker(ctx, i)
	}
	log.Printf("Started %d email workers", numWorkers)
}

func (w *EmailWorker) worker(ctx context.Context, id int) {
	log.Printf("Email worker %d started", id)
	for {
		select {
		case <-ctx.Done():
			log.Printf("Email worker %d stopped", id)
			return
		case job := <-w.jobQueue.jobs:
			w.processJob(job, id)
		}
	}
}

func (w *EmailWorker) processJob(job email.EmailJob, workerID int) {
	if err := w.provider.Send(job.To, job.Subject, job.Body); err != nil {
		log.Printf("Worker %d: Failed to send email to %s: %v", workerID, job.To, err)
		return
	}
	log.Printf("Worker %d: Successfully sent email to %s", workerID, job.To)
}
