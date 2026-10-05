// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package db_test

import (
	"context"
	"errors"
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndependentSnapshotTransaction(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	var outerEngine db.Engine
	var closedTx context.Context
	rollback := errors.New("business rollback")
	valueKey := struct{ name string }{"safe request"}
	ctx := context.WithValue(t.Context(), valueKey, "request-1")
	err := db.WithTx(ctx, func(tx context.Context) error {
		outerEngine = db.GetEngine(tx)
		closedTx = tx
		called := false
		err := db.WithIndependentReadTx(tx, func(context.Context) error { called = true; return nil })
		require.ErrorIs(t, err, db.ErrIndependentTransactionInUse)
		require.False(t, called)
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	require.NoError(t, db.WithIndependentReadTx(closedTx, func(snapshot context.Context) error {
		require.Equal(t, "request-1", snapshot.Value(valueKey))
		require.True(t, db.InTransaction(snapshot))
		require.NotSame(t, outerEngine, db.GetEngine(snapshot))
		return nil
	}))
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	err = db.WithIndependentReadTx(canceled, func(context.Context) error { called = true; return nil })
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)
}

func TestIndependentTransactionRejectsBusinessTransaction(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	called := false
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		err := db.WithIndependentTx(ctx, func(context.Context) error { called = true; return nil })
		require.ErrorIs(t, err, db.ErrIndependentTransactionInUse)
		return nil
	}))
	require.False(t, called)
}

func TestInTransaction(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	assert.False(t, db.InTransaction(t.Context()))
	assert.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		assert.True(t, db.InTransaction(ctx))
		return nil
	}))

	ctx, committer, err := db.TxContext(t.Context())
	assert.NoError(t, err)
	defer committer.Close()
	assert.True(t, db.InTransaction(ctx))
	assert.NoError(t, db.WithTx(ctx, func(ctx context.Context) error {
		assert.True(t, db.InTransaction(ctx))
		return nil
	}))
}

func TestTxContext(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())

	{ // create new transaction
		ctx, committer, err := db.TxContext(t.Context())
		assert.NoError(t, err)
		assert.True(t, db.InTransaction(ctx))
		assert.NoError(t, committer.Commit())
	}

	{ // reuse the transaction created by TxContext and commit it
		ctx, committer, err := db.TxContext(t.Context())
		engine := db.GetEngine(ctx)
		assert.NoError(t, err)
		assert.True(t, db.InTransaction(ctx))
		{
			ctx, committer, err := db.TxContext(ctx)
			assert.NoError(t, err)
			assert.True(t, db.InTransaction(ctx))
			assert.Equal(t, engine, db.GetEngine(ctx))
			assert.NoError(t, committer.Commit())
		}
		assert.NoError(t, committer.Commit())
	}

	{ // reuse the transaction created by TxContext and close it
		ctx, committer, err := db.TxContext(t.Context())
		engine := db.GetEngine(ctx)
		assert.NoError(t, err)
		assert.True(t, db.InTransaction(ctx))
		{
			ctx, committer, err := db.TxContext(ctx)
			assert.NoError(t, err)
			assert.True(t, db.InTransaction(ctx))
			assert.Equal(t, engine, db.GetEngine(ctx))
			assert.NoError(t, committer.Close())
		}
		assert.NoError(t, committer.Close())
	}

	{ // reuse the transaction created by WithTx
		assert.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
			assert.True(t, db.InTransaction(ctx))
			{
				ctx, committer, err := db.TxContext(ctx)
				assert.NoError(t, err)
				assert.True(t, db.InTransaction(ctx))
				assert.NoError(t, committer.Commit())
			}
			return nil
		}))
	}
}

func TestContextSafety(t *testing.T) {
	type TestModel1 struct {
		ID int64
	}
	type TestModel2 struct {
		ID int64
	}
	assert.NoError(t, unittest.GetXORMEngine().Sync(&TestModel1{}, &TestModel2{}))
	assert.NoError(t, db.TruncateBeans(t.Context(), &TestModel1{}, &TestModel2{}))
	testCount := 10
	for i := 1; i <= testCount; i++ {
		assert.NoError(t, db.Insert(t.Context(), &TestModel1{ID: int64(i)}))
		assert.NoError(t, db.Insert(t.Context(), &TestModel2{ID: int64(-i)}))
	}

	t.Run("Show-XORM-Bug", func(t *testing.T) {
		actualCount := 0
		// here: db.GetEngine(t.Context()) is a new *Session created from *Engine
		_ = db.WithTx(t.Context(), func(ctx context.Context) error {
			_ = db.GetEngine(ctx).Iterate(&TestModel1{}, func(i int, bean any) error {
				// here: db.GetEngine(ctx) is always the unclosed "Iterate" *Session with autoResetStatement=false,
				// and the internal states (including "cond" and others) are always there and not be reset in this callback.
				m1, ok := bean.(*TestModel1)
				require.True(t, ok)
				assert.EqualValues(t, i+1, m1.ID)

				// here: XORM bug, it fails because the SQL becomes "WHERE id=-1", "WHERE id=-1 AND id=-2", "WHERE id=-1 AND id=-2 AND id=-3" ...
				// and it conflicts with the "Iterate"'s internal states.
				// has, err := db.GetEngine(ctx).Get(&TestModel2{ID: -m1.ID})

				actualCount++
				return nil
			})
			return nil
		})
		assert.Equal(t, testCount, actualCount)
	})

	t.Run("DenyBadUsage", func(t *testing.T) {
		assert.PanicsWithError(t, "using session context in an iterator would cause corrupted results", func() {
			_ = db.WithTx(t.Context(), func(ctx context.Context) error {
				return db.GetEngine(ctx).Iterate(&TestModel1{}, func(i int, bean any) error {
					_ = db.GetEngine(ctx)
					return nil
				})
			})
		})
	})
}

func TestPostCommitEffectsOnlyRunAfterOuterCommit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	count := 0
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		return db.WithTx(ctx, func(ctx context.Context) error {
			db.AfterCommit(ctx, func() { count++ })
			require.Zero(t, count)
			return nil
		})
	}))
	require.Equal(t, 1, count)
	require.Error(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		db.AfterCommit(ctx, func() { count++ })
		return context.Canceled
	}))
	require.Equal(t, 1, count)
}

func TestPostCommitEffectsDoNotRunWhenNestedFailureIsIgnored(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	count := 0
	err := db.WithTx(t.Context(), func(ctx context.Context) error {
		db.AfterCommit(ctx, func() { count++ })
		_ = db.WithTx(ctx, func(context.Context) error { return context.Canceled })
		return nil
	})
	require.Error(t, err)
	require.Zero(t, count)
}

func TestPostRollbackEffectsOnlyRunAfterOutermostClose(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	count := 0
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		db.AfterRollback(ctx, func() { count++ })
		return nil
	}))
	require.Zero(t, count)
	err := db.WithTx(t.Context(), func(ctx context.Context) error {
		_ = db.WithTx(ctx, func(ctx context.Context) error {
			db.AfterRollback(ctx, func() {
				count++
				require.NoError(t, db.WithIndependentTx(ctx, func(context.Context) error { return nil }))
			})
			return context.Canceled
		})
		require.Zero(t, count)
		return nil
	})
	require.Error(t, err)
	require.Equal(t, 1, count)
}

func TestSavepointKeepsOuterTransactionUsable(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		err := db.WithSavepoint(ctx, func(tx context.Context) error {
			_, err := db.Exec(tx, "UPDATE repository SET description=? WHERE id=1", "must-be-rolled-back")
			require.NoError(t, err)
			_, err = db.Exec(tx, "SELECT * FROM missing_observation_table")
			return err
		})
		require.Error(t, err)
		rows, err := db.GetEngine(ctx).Query("SELECT description FROM repository WHERE id=1")
		require.NoError(t, err)
		require.NotEqual(t, "must-be-rolled-back", string(rows[0]["description"]))
		_, err = db.Exec(ctx, "UPDATE repository SET description=? WHERE id=1", "native-committed")
		return err
	}))
	rows, err := db.GetEngine(t.Context()).Query("SELECT description FROM repository WHERE id=1")
	require.NoError(t, err)
	require.Equal(t, "native-committed", string(rows[0]["description"]))
	require.NoError(t, db.WithIndependentReadTx(t.Context(), func(ctx context.Context) error {
		require.True(t, db.IsReadOnly(ctx))
		return nil
	}))
	require.False(t, db.IsReadOnly(t.Context()))
}

func TestReadOnlyMarkerDoesNotLeakIntoNewWriteTransaction(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	var closed context.Context
	require.NoError(t, db.WithIndependentReadTx(t.Context(), func(ctx context.Context) error {
		closed = ctx
		require.True(t, db.IsReadOnly(ctx))
		return nil
	}))
	for _, open := range []func(context.Context, func(context.Context) error) error{db.WithTx, db.WithIndependentTx} {
		require.NoError(t, open(closed, func(ctx context.Context) error {
			require.False(t, db.IsReadOnly(ctx))
			return nil
		}))
	}
}

func TestNestedSavepointCancellationPreservesNativeCommit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	committed := false
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error {
		db.AfterCommit(tx, func() { committed = true })
		bounded, cancel := context.WithCancel(tx)
		defer cancel()
		err := db.WithSavepoint(bounded, func(outer context.Context) error {
			return db.WithSavepoint(outer, func(context.Context) error {
				cancel()
				return context.Canceled
			})
		})
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, db.ErrObservationTransactionUnavailable)
		_, err = db.Exec(tx, "UPDATE repository SET description = ? WHERE id = ?", "nested observation survived", 1)
		return err
	}))
	require.True(t, committed)
}
