using System.Buffers;
using System.Collections;
using JetBrains.Annotations;

namespace FileEncrypter;

/// <summary>
/// A pooled array wrapper
/// </summary>
/// <param name="length">Length of the pooled array to create</param>
/// <typeparam name="T">Array element type</typeparam>
[PublicAPI]
public struct PooledArray<T>(int length) : IList<T>, IDisposable
{
    private bool isDisposed;
    private readonly T[] array = ArrayPool<T>.Shared.Rent(length);
    private static readonly Type SelfType = typeof(PooledArray<T>);

    /// <inheritdoc cref="System.Array.Length"/>
    public int Length { get; } = length;

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly T this[int index]
    {
        get => this.AsSpan[index];
        set => this.AsSpan[index] = value;
    }

    /// <inheritdoc cref="System.Span{T}.Item(System.Int32)"/>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly T this[Index index]
    {
        get => this.AsSpan[index];
        set => this.AsSpan[index] = value;
    }

    /// <summary>
    /// Forms a slice of the given array across the specified range
    /// </summary>
    /// <param name="range">Index range to get the slice for</param>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly Span<T> this[Range range] => this.AsSpan[range];

    /// <summary>
    /// Gets a span of the given pooled array
    /// </summary>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly Span<T> AsSpan
    {
        get
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, typeof(PooledArray<T>));
            return this.array.AsSpan(0, this.Length);
        }
    }

    /// <summary>
    /// Gets a memory block of the given pooled array
    /// </summary>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly Memory<T> AsMemory
    {
        get
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, typeof(PooledArray<T>));
            return this.array.AsMemory(0, this.Length);
        }
    }

    /// <summary>
    /// Gets the raw underlying array of this pooled array.<br/>
    /// </summary>
    /// <remarks><b>WARNING</b>: The length of the actual array may be larger than the requested length of the pooled array.</remarks>
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly T[] AsRawArray
    {
        get
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, typeof(PooledArray<T>));
            return this.array;
        }
    }

    /// <summary>
    /// Gets a reference to the element at the specified zero-based index.
    /// </summary>
    /// <returns>A reference to the element at the specified index.</returns>
    /// <inheritdoc cref="Item(System.Int32)"/>
    public readonly ref T GetRef(int index) => ref this.AsSpan[index];

    /// <inheritdoc cref="GetRef(System.Int32)"/>
    public readonly ref T GetRef(Index index) => ref this.AsSpan[index];

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly bool Contains(T item) => this.AsSpan.Contains(item);

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly void CopyTo(T[] otherArray, int arrayIndex) => this.AsSpan.CopyTo(otherArray.AsSpan(arrayIndex));

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly int IndexOf(T item) => this.AsSpan.IndexOf(item);

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly void Clear() => this.AsSpan.Clear();

    /// <inheritdoc cref="IEnumerable{T}.GetEnumerator()" />
    /// <exception cref="ObjectDisposedException">If the pooled array has already been returned</exception>
    public readonly Enumerator GetEnumerator()
    {
        ObjectDisposedException.ThrowIf(this.isDisposed, typeof(PooledArray<T>));
        return new Enumerator(this);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (this.isDisposed) return;

        this.isDisposed = true;
        ArrayPool<T>.Shared.Return(this.array);
    }

    readonly int ICollection<T>.Count => this.array.Length;
    readonly bool ICollection<T>.IsReadOnly => this.array.IsReadOnly;
    readonly void ICollection<T>.Add(T item) => ((ICollection<T>)this.array).Add(item);
    readonly bool ICollection<T>.Remove(T item) => ((ICollection<T>)this.array).Remove(item);
    readonly void IList<T>.Insert(int index, T item) => ((IList<T>)this.array).Insert(index, item);
    readonly void IList<T>.RemoveAt(int index) => ((IList<T>)this.array).RemoveAt(index);
    readonly IEnumerator<T> IEnumerable<T>.GetEnumerator() => GetEnumerator();
    readonly IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public struct Enumerator(PooledArray<T> pooledArray) : IEnumerator<T>
    {
        private int index = -1;
        private readonly PooledArray<T> pooledArray = pooledArray;

        /// <inheritdoc />
        public readonly T Current => this.pooledArray.AsSpan[this.index];

        /// <inheritdoc />
        public bool MoveNext() => ++this.index < this.pooledArray.Length;

        readonly object? IEnumerator.Current => this.pooledArray.AsSpan[this.index];
        void IEnumerator.Reset() => this.index = -1;
        readonly void IDisposable.Dispose() { }
    }
}
